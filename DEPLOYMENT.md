# Google Cloud deployment

ตัวอย่างใช้ region `asia-southeast1`; เปลี่ยนตัวแปรก่อนรัน ต้องมีสิทธิ์เปิด API, build image, deploy Cloud Run, create Firestore และ IAM

## 1. เตรียม project

```bash
export PROJECT_ID="your-project-id"
export REGION="asia-southeast1"
export REPOSITORY="aegis"
gcloud config set project "$PROJECT_ID"
gcloud services enable run.googleapis.com artifactregistry.googleapis.com cloudbuild.googleapis.com firestore.googleapis.com aiplatform.googleapis.com
gcloud artifacts repositories create "$REPOSITORY" --repository-format=docker --location="$REGION"
gcloud firestore databases create --location="$REGION"
```

หากมี Firestore database แล้ว ไม่ต้องรันคำสั่ง create ซ้ำ

## 2. Service accounts และ IAM

```bash
gcloud iam service-accounts create aegis-web
gcloud iam service-accounts create aegis-scanner
gcloud projects add-iam-policy-binding "$PROJECT_ID" --member="serviceAccount:aegis-web@$PROJECT_ID.iam.gserviceaccount.com" --role="roles/datastore.user"
gcloud projects add-iam-policy-binding "$PROJECT_ID" --member="serviceAccount:aegis-web@$PROJECT_ID.iam.gserviceaccount.com" --role="roles/run.developer"
gcloud projects add-iam-policy-binding "$PROJECT_ID" --member="serviceAccount:aegis-scanner@$PROJECT_ID.iam.gserviceaccount.com" --role="roles/datastore.user"
```

ปรับ IAM ให้แคบลงใน production และเพิ่ม policy/conditional permissions ตามองค์กร

## 3. Build images

```bash
gcloud builds submit --tag "$REGION-docker.pkg.dev/$PROJECT_ID/$REPOSITORY/web:1.0.0" -f Dockerfile.web .
gcloud builds submit --tag "$REGION-docker.pkg.dev/$PROJECT_ID/$REPOSITORY/scanner:1.0.0" -f Dockerfile.scanner .
```

## 4. Deploy Scanner Job ก่อน

```bash
gcloud run jobs deploy zap-scanner \
  --image "$REGION-docker.pkg.dev/$PROJECT_ID/$REPOSITORY/scanner:1.0.0" \
  --region "$REGION" --service-account "aegis-scanner@$PROJECT_ID.iam.gserviceaccount.com" \
  --cpu 2 --memory 4Gi --task-timeout 30m --max-retries 0 \
  --set-env-vars "GOOGLE_CLOUD_PROJECT=$PROJECT_ID,SCAN_TIMEOUT_SECONDS=1800"
```

## 5. Deploy Web Service

```bash
gcloud run deploy aegis-web \
  --image "$REGION-docker.pkg.dev/$PROJECT_ID/$REPOSITORY/web:1.0.0" \
  --region "$REGION" --service-account "aegis-web@$PROJECT_ID.iam.gserviceaccount.com" \
  --allow-unauthenticated --cpu 1 --memory 512Mi --min 0 --max 5 --concurrency 40 \
  --set-env-vars "APP_ENV=production,STORE_BACKEND=firestore,GOOGLE_CLOUD_PROJECT=$PROJECT_ID,CLOUD_RUN_REGION=$REGION,SCANNER_JOB_NAME=zap-scanner,MAX_ACTIVE_SCANS=3"
```

ให้ Web service account มี `run.jobs.run` สำหรับ job นี้โดยเฉพาะ ตรวจ `/health`, ทำ Quick Scan กับโดเมนที่ได้รับอนุญาต และตรวจ Firestore collections `scans`, `alerts`, `audit_logs`

## Production checklist

- ใช้ custom domain + HTTPS, Cloud Armor rate limit และ authenticated session/consent audit
- จำกัด outbound network และตรวจ DNS/IP/redirect ซ้ำที่ Job เพื่อป้องกัน SSRF/DNS rebinding
- เก็บ Gemini secret ใน Secret Manager และ mount ด้วย `--set-secrets`; ห้าม hardcode
- ตั้ง Firestore TTL สำหรับ audit/scan retention, log exclusion และ budget alerts
- จำกัด global/job parallelism; monitor failed executions, timeout และ ZAP resource use
- สแกน container images, pin digest หลังผ่าน staging และทำ rollback revision test

