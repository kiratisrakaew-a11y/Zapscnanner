#!/usr/bin/env bash
#
# deploy.sh — Deploy Aegis (ZAP Security Scanner) to Google Cloud Run.
#
# Deploys the FastAPI web service + the ZAP scanner Cloud Run Job, backed by
# Firestore, with the Gemini API key stored in Secret Manager. Idempotent:
# re-running skips resources that already exist and rolls out new revisions.
#
# Run this on a machine where `gcloud` is installed and authenticated
# (`gcloud auth login`). It cannot run from an unauthenticated container.
#
# Usage:
#   export PROJECT_ID=your-project-id
#   export GEMINI_API_KEY=your-gemini-key      # required (Gemini enabled)
#   ./deploy.sh
#
# Optional overrides:
#   REGION=asia-southeast1  REPOSITORY=aegis  VERSION=1.0.0  GEMINI_MODEL=gemini-2.5-flash

set -euo pipefail

# --- configuration ----------------------------------------------------------
: "${PROJECT_ID:?ต้องตั้ง PROJECT_ID เช่น: export PROJECT_ID=my-project}"
: "${GEMINI_API_KEY:?ต้องตั้ง GEMINI_API_KEY สำหรับเปิดใช้ Gemini เช่น: export GEMINI_API_KEY=xxxx}"
REGION="${REGION:-asia-southeast1}"
REPOSITORY="${REPOSITORY:-aegis}"
VERSION="${VERSION:-1.0.0}"
GEMINI_MODEL="${GEMINI_MODEL:-gemini-2.5-flash}"

WEB_SA="aegis-web@${PROJECT_ID}.iam.gserviceaccount.com"
SCANNER_SA="aegis-scanner@${PROJECT_ID}.iam.gserviceaccount.com"
REGISTRY="${REGION}-docker.pkg.dev/${PROJECT_ID}/${REPOSITORY}"
WEB_IMAGE="${REGISTRY}/web:${VERSION}"
SCANNER_IMAGE="${REGISTRY}/scanner:${VERSION}"
GEMINI_SECRET="gemini-api-key"

log() { printf '\n\033[1;36m==> %s\033[0m\n' "$*"; }

# --- 0. preflight -----------------------------------------------------------
command -v gcloud >/dev/null 2>&1 || { echo "ไม่พบ gcloud CLI — ติดตั้งก่อน: https://cloud.google.com/sdk/docs/install" >&2; exit 1; }
gcloud auth list --filter=status:ACTIVE --format="value(account)" | grep -q . \
  || { echo "ยังไม่ได้ล็อกอิน — รัน: gcloud auth login" >&2; exit 1; }
log "ใช้ project=${PROJECT_ID} region=${REGION} version=${VERSION}"
gcloud config set project "$PROJECT_ID" >/dev/null

# --- 1. enable APIs ---------------------------------------------------------
log "เปิดใช้งาน APIs"
gcloud services enable \
  run.googleapis.com artifactregistry.googleapis.com cloudbuild.googleapis.com \
  firestore.googleapis.com aiplatform.googleapis.com secretmanager.googleapis.com

# --- 2. Artifact Registry ---------------------------------------------------
log "สร้าง Artifact Registry (ข้ามถ้ามีแล้ว)"
gcloud artifacts repositories describe "$REPOSITORY" --location="$REGION" >/dev/null 2>&1 \
  || gcloud artifacts repositories create "$REPOSITORY" --repository-format=docker --location="$REGION"

# --- 3. Firestore -----------------------------------------------------------
log "สร้าง Firestore database (ข้ามถ้ามีแล้ว)"
gcloud firestore databases describe --database="(default)" >/dev/null 2>&1 \
  || gcloud firestore databases create --location="$REGION"

# --- 4. service accounts ----------------------------------------------------
log "สร้าง service accounts (ข้ามถ้ามีแล้ว)"
gcloud iam service-accounts describe "$WEB_SA" >/dev/null 2>&1 \
  || gcloud iam service-accounts create aegis-web
gcloud iam service-accounts describe "$SCANNER_SA" >/dev/null 2>&1 \
  || gcloud iam service-accounts create aegis-scanner

# --- 5. IAM bindings --------------------------------------------------------
log "ผูกสิทธิ์ IAM"
gcloud projects add-iam-policy-binding "$PROJECT_ID" --member="serviceAccount:${WEB_SA}"     --role="roles/datastore.user" --condition=None >/dev/null
gcloud projects add-iam-policy-binding "$PROJECT_ID" --member="serviceAccount:${WEB_SA}"     --role="roles/run.developer"  --condition=None >/dev/null
gcloud projects add-iam-policy-binding "$PROJECT_ID" --member="serviceAccount:${SCANNER_SA}" --role="roles/datastore.user" --condition=None >/dev/null

# --- 6. Gemini secret (Secret Manager) --------------------------------------
log "เก็บ GEMINI_API_KEY ใน Secret Manager"
if gcloud secrets describe "$GEMINI_SECRET" >/dev/null 2>&1; then
  printf '%s' "$GEMINI_API_KEY" | gcloud secrets versions add "$GEMINI_SECRET" --data-file=-
else
  printf '%s' "$GEMINI_API_KEY" | gcloud secrets create "$GEMINI_SECRET" --replication-policy=automatic --data-file=-
fi
gcloud secrets add-iam-policy-binding "$GEMINI_SECRET" \
  --member="serviceAccount:${WEB_SA}" --role="roles/secretmanager.secretAccessor" >/dev/null

# --- 7. build images --------------------------------------------------------
# gcloud builds submit --tag builds only the default "Dockerfile"; to build a
# named Dockerfile we submit a generated Cloud Build config whose docker step
# takes -f.
build_image() {           # $1=Dockerfile  $2=image
  local cfg; cfg="$(mktemp)"
  cat >"$cfg" <<EOF
steps:
  - name: gcr.io/cloud-builders/docker
    args: ["build", "-f", "$1", "-t", "$2", "."]
images:
  - "$2"
EOF
  gcloud builds submit --config "$cfg" .
  rm -f "$cfg"
}
log "Build web image"
build_image Dockerfile.web "$WEB_IMAGE"
log "Build scanner image"
build_image Dockerfile.scanner "$SCANNER_IMAGE"

# --- 8. deploy scanner Job (ก่อน web) ---------------------------------------
log "Deploy scanner Cloud Run Job"
gcloud run jobs deploy zap-scanner \
  --image "$SCANNER_IMAGE" --region "$REGION" --service-account "$SCANNER_SA" \
  --cpu 2 --memory 4Gi --task-timeout 30m --max-retries 0 \
  --set-env-vars "GOOGLE_CLOUD_PROJECT=${PROJECT_ID},SCAN_TIMEOUT_SECONDS=1800"

# --- 9. deploy web Service --------------------------------------------------
log "Deploy web Cloud Run Service"
gcloud run deploy aegis-web \
  --image "$WEB_IMAGE" --region "$REGION" --service-account "$WEB_SA" \
  --allow-unauthenticated --cpu 1 --memory 512Mi --min 0 --max 5 --concurrency 40 \
  --set-env-vars "APP_ENV=production,STORE_BACKEND=firestore,GOOGLE_CLOUD_PROJECT=${PROJECT_ID},CLOUD_RUN_REGION=${REGION},SCANNER_JOB_NAME=zap-scanner,MAX_ACTIVE_SCANS=3,GEMINI_MODEL=${GEMINI_MODEL}" \
  --set-secrets "GEMINI_API_KEY=${GEMINI_SECRET}:latest"

# --- 10. post-deploy --------------------------------------------------------
URL="$(gcloud run services describe aegis-web --region "$REGION" --format='value(status.url)')"
log "Deploy สำเร็จ — Service URL: ${URL}"
echo "ตรวจ health: curl ${URL}/health"
if command -v curl >/dev/null 2>&1; then
  echo -n "health -> "; curl -s "${URL}/health" || true; echo
fi
