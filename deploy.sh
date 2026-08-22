#!/usr/bin/env bash
#
# deploy.sh — Deploy Aegis (ZAP Security Scanner) to Google Cloud Run.
#
# Deploys the FastAPI web service + the ZAP scanner Cloud Run Job, backed by
# Firestore, with the OpenAI API key stored in Secret Manager. Idempotent:
# re-running skips resources that already exist and rolls out new revisions.
#
# Run this on a machine where `gcloud` is installed and authenticated
# (`gcloud auth login`). It cannot run from an unauthenticated container.
#
# Usage:
#   export PROJECT_ID=your-project-id
#   export OPENAI_API_KEY=your-openai-key      # required (AI enrichment enabled)
#   ./deploy.sh
#
# Optional overrides:
#   REGION=asia-southeast1  REPOSITORY=aegis  VERSION=1.0.0
#   OPENAI_MODEL=gpt-4o-mini  OPENAI_BASE_URL=      # base_url for OpenAI-compatible endpoints

set -euo pipefail

# --- configuration ----------------------------------------------------------
: "${PROJECT_ID:?ต้องตั้ง PROJECT_ID เช่น: export PROJECT_ID=my-project}"
: "${OPENAI_API_KEY:?ต้องตั้ง OPENAI_API_KEY สำหรับเปิดใช้ AI เช่น: export OPENAI_API_KEY=sk-...}"
REGION="${REGION:-asia-southeast1}"
REPOSITORY="${REPOSITORY:-aegis}"
VERSION="${VERSION:-1.0.0}"
OPENAI_MODEL="${OPENAI_MODEL:-gpt-4o-mini}"
OPENAI_BASE_URL="${OPENAI_BASE_URL:-}"
# Email report (optional): set SMTP_USER + SMTP_PASSWORD (Gmail App Password) to enable
SMTP_USER="${SMTP_USER:-}"
SMTP_PASSWORD="${SMTP_PASSWORD:-}"
SMTP_HOST="${SMTP_HOST:-smtp.gmail.com}"
SMTP_PORT="${SMTP_PORT:-587}"
SMTP_FROM="${SMTP_FROM:-$SMTP_USER}"
SMTP_SECRET="smtp-password"

WEB_SA="aegis-web@${PROJECT_ID}.iam.gserviceaccount.com"
SCANNER_SA="aegis-scanner@${PROJECT_ID}.iam.gserviceaccount.com"
REGISTRY="${REGION}-docker.pkg.dev/${PROJECT_ID}/${REPOSITORY}"
WEB_IMAGE="${REGISTRY}/web:${VERSION}"
SCANNER_IMAGE="${REGISTRY}/scanner:${VERSION}"
OPENAI_SECRET="openai-api-key"

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

# --- 6. OpenAI secret (Secret Manager) --------------------------------------
log "เก็บ OPENAI_API_KEY ใน Secret Manager"
if gcloud secrets describe "$OPENAI_SECRET" >/dev/null 2>&1; then
  printf '%s' "$OPENAI_API_KEY" | gcloud secrets versions add "$OPENAI_SECRET" --data-file=-
else
  printf '%s' "$OPENAI_API_KEY" | gcloud secrets create "$OPENAI_SECRET" --replication-policy=automatic --data-file=-
fi
gcloud secrets add-iam-policy-binding "$OPENAI_SECRET" \
  --member="serviceAccount:${WEB_SA}" --role="roles/secretmanager.secretAccessor" >/dev/null
# Scanner job also needs the key to generate AI fix prompts for the email/report.
gcloud secrets add-iam-policy-binding "$OPENAI_SECRET" \
  --member="serviceAccount:${SCANNER_SA}" --role="roles/secretmanager.secretAccessor" >/dev/null

# --- 6b. SMTP secret (optional email report) --------------------------------
if [ -n "$SMTP_USER" ] && [ -n "$SMTP_PASSWORD" ]; then
  log "เก็บ SMTP_PASSWORD ใน Secret Manager (เปิดใช้ email report)"
  if gcloud secrets describe "$SMTP_SECRET" >/dev/null 2>&1; then
    printf '%s' "$SMTP_PASSWORD" | gcloud secrets versions add "$SMTP_SECRET" --data-file=-
  else
    printf '%s' "$SMTP_PASSWORD" | gcloud secrets create "$SMTP_SECRET" --replication-policy=automatic --data-file=-
  fi
  gcloud secrets add-iam-policy-binding "$SMTP_SECRET" \
    --member="serviceAccount:${SCANNER_SA}" --role="roles/secretmanager.secretAccessor" >/dev/null
fi

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
# OPENAI_* lets the scanner generate AI fix prompts for High/Medium findings
# (shown on the result page + included in the email). Only set OPENAI_BASE_URL when
# non-empty — an empty value makes the OpenAI SDK build a scheme-less URL.
SCANNER_ENV="GOOGLE_CLOUD_PROJECT=${PROJECT_ID},SCAN_TIMEOUT_SECONDS=1800,OPENAI_MODEL=${OPENAI_MODEL}"
if [ -n "$OPENAI_BASE_URL" ]; then SCANNER_ENV="${SCANNER_ENV},OPENAI_BASE_URL=${OPENAI_BASE_URL}"; fi
SCANNER_SECRETS="OPENAI_API_KEY=${OPENAI_SECRET}:latest"
if [ -n "$SMTP_USER" ] && [ -n "$SMTP_PASSWORD" ]; then
  SCANNER_ENV="${SCANNER_ENV},SMTP_HOST=${SMTP_HOST},SMTP_PORT=${SMTP_PORT},SMTP_USER=${SMTP_USER},SMTP_FROM=${SMTP_FROM}"
  SCANNER_SECRETS="${SCANNER_SECRETS},SMTP_PASSWORD=${SMTP_SECRET}:latest"
fi
gcloud run jobs deploy zap-scanner \
  --image "$SCANNER_IMAGE" --region "$REGION" --service-account "$SCANNER_SA" \
  --cpu 2 --memory 8Gi --task-timeout 30m --max-retries 0 \
  --set-env-vars "$SCANNER_ENV" --set-secrets "$SCANNER_SECRETS"

# --- 9. deploy web Service --------------------------------------------------
log "Deploy web Cloud Run Service"
# Only set OPENAI_BASE_URL when non-empty. Setting it to "" makes the OpenAI SDK
# use an empty (scheme-less) base URL, which fails with UnsupportedProtocol.
WEB_ENV="APP_ENV=production,STORE_BACKEND=firestore,GOOGLE_CLOUD_PROJECT=${PROJECT_ID},CLOUD_RUN_REGION=${REGION},SCANNER_JOB_NAME=zap-scanner,MAX_ACTIVE_SCANS=3,OPENAI_MODEL=${OPENAI_MODEL}"
if [ -n "$OPENAI_BASE_URL" ]; then WEB_ENV="${WEB_ENV},OPENAI_BASE_URL=${OPENAI_BASE_URL}"; fi
gcloud run deploy aegis-web \
  --image "$WEB_IMAGE" --region "$REGION" --service-account "$WEB_SA" \
  --allow-unauthenticated --cpu 1 --memory 512Mi --min 0 --max 5 --concurrency 40 \
  --set-env-vars "$WEB_ENV" \
  --set-secrets "OPENAI_API_KEY=${OPENAI_SECRET}:latest"

# --- 10. post-deploy --------------------------------------------------------
URL="$(gcloud run services describe aegis-web --region "$REGION" --format='value(status.url)')"
log "Deploy สำเร็จ — Service URL: ${URL}"
echo "ตรวจ health: curl ${URL}/health"
if command -v curl >/dev/null 2>&1; then
  echo -n "health -> "; curl -s "${URL}/health" || true; echo
fi
