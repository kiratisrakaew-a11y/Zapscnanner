# Aegis — OWASP ZAP Security Scanner V1

เว็บสำหรับประเมินเว็บไซต์สาธารณะจาก URL ด้วย OWASP ZAP โดยแยก FastAPI Web Service ออกจาก Scanner Job รายงานเน้นภาษาไทยแบบ Business First และเก็บผลใน Firestore

## Local setup (Phase 1: fake scan)

ต้องมี Python 3.12+ และ Docker (สำหรับ Phase 2)

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
cp .env.example .env
uvicorn web.main:app --reload --port 8080
```

เปิด <http://localhost:8080> ค่าเริ่มต้น `APP_ENV=development` และ `STORE_BACKEND=memory` จะใช้ fake scan เพื่อทดสอบ UI โดยไม่ยิงเป้าหมายจริง ข้อมูลจะหายเมื่อ restart

```bash
pytest -q
docker build -f Dockerfile.web -t aegis-web .
docker run --rm -p 8080:8080 --env-file .env aegis-web
```

## Local ZAP smoke test

ใช้เฉพาะ target ที่ได้รับอนุญาต แนะนำ OWASP Juice Shop ใน Docker network แยก:

```bash
docker network create zap-lab
docker run -d --rm --name juice-shop --network zap-lab bkimminich/juice-shop
docker run --rm --network zap-lab -v "$PWD/scanner:/zap/wrk/scanner:ro" \
  -e TARGET_URL=http://juice-shop:3000 zaproxy/zap-stable:2.16.1 \
  zap.sh -cmd -autorun /zap/wrk/scanner/zap_quick.yaml
```

Production flow ไม่ให้ Web Service รอ scan: API บันทึก `QUEUED` แล้วเรียก Cloud Run Job; Job รัน Automation Framework, parse JSON และเขียน findings กลับ Firestore

## Configuration

ดูค่าทั้งหมดใน `.env.example` ห้าม commit `.env` หรือ service-account key. Production ต้องตั้ง `APP_ENV=production`, `STORE_BACKEND=firestore`, project/region/job และ random `SCAN_TOKEN_SECRET` ผ่าน Secret Manager หรือ Cloud Run environment variables. `GEMINI_API_KEY` เป็น optional; หาก AI ล้มเหลวผล ZAP ยังต้องแสดงได้

## API

- `POST /api/scans` — สร้างงาน (ต้องส่ง `authorization_confirmed: true`)
- `GET /api/scans/{scan_id}` — poll ทุก 3–5 วินาที
- `GET /api/scans/{scan_id}/findings`
- `GET /api/scans` — ประวัติ
- `POST /api/scans/{scan_id}/cancel`
- `GET /health`

> V1 รองรับเฉพาะ unauthenticated public web targets. Score เป็น indicator จาก ZAP findings ไม่ใช่หลักฐานว่าระบบปลอดภัยทั้งหมด

