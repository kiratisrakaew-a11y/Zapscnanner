from datetime import datetime, timezone
from uuid import uuid4
from fastapi import APIRouter, Depends, HTTPException, Request
from web.models import Scan, ScanCreate, ScanStatus
from web.services.url_validation import UnsafeTarget, validate_target

router = APIRouter(prefix="/api/scans", tags=["scans"])

def state(request: Request): return request.app.state

@router.post("", status_code=202)
async def create_scan(payload: ScanCreate, request: Request, app=Depends(state)):
    if not payload.authorization_confirmed:
        raise HTTPException(400, "ต้องยืนยันสิทธิ์ก่อนเริ่มการประเมิน")
    session_id = request.headers.get("X-Session-ID", request.client.host if request.client else "unknown")
    active_for_session = [s for s in app.store.list_scans() if s.session_id == session_id and s.status not in {ScanStatus.COMPLETED, ScanStatus.FAILED, ScanStatus.CANCELLED}]
    if active_for_session:
        raise HTTPException(429, "อนุญาตให้มีงานที่กำลังทำงานได้หนึ่งรายการต่อ session")
    if app.store.active_count() >= app.settings.max_active_scans:
        raise HTTPException(429, "ระบบมีงานเต็ม กรุณาลองใหม่ภายหลัง")
    try: await validate_target(str(payload.target_url), resolve_dns=app.settings.app_env != "test")
    except UnsafeTarget as exc: raise HTTPException(400, str(exc)) from exc
    scan_id = "SCAN-" + uuid4().hex[:8].upper()
    scan = Scan(scan_id=scan_id, target=str(payload.target_url), scan_type=payload.scan_type, session_id=session_id)
    audit = {"scan_id": scan_id, "target": scan.target, "authorization_confirmed": True, "timestamp": datetime.now(timezone.utc).isoformat(), "session_identifier": session_id}
    app.store.create_scan(scan, audit)
    try: await app.scanner.dispatch(scan)
    except Exception as exc:
        scan.status, scan.error_code, scan.error_message = ScanStatus.FAILED, "JOB_DISPATCH_FAILED", "ไม่สามารถเริ่ม Scanner Job ได้"
        app.store.update_scan(scan)
        raise HTTPException(503, "ไม่สามารถเริ่มงานประเมินได้") from exc
    return {"scan_id": scan_id, "status": scan.status}

@router.get("")
def list_scans(app=Depends(state)): return app.store.list_scans()

@router.get("/{scan_id}")
def get_scan(scan_id: str, app=Depends(state)):
    scan = app.store.get_scan(scan_id)
    if not scan: raise HTTPException(404, "ไม่พบ Scan")
    return scan

@router.get("/{scan_id}/findings")
def findings(scan_id: str, app=Depends(state)):
    if not app.store.get_scan(scan_id): raise HTTPException(404, "ไม่พบ Scan")
    return app.store.get_findings(scan_id)

@router.post("/{scan_id}/cancel")
def cancel(scan_id: str, app=Depends(state)):
    scan = app.store.get_scan(scan_id)
    if not scan: raise HTTPException(404, "ไม่พบ Scan")
    if scan.status in {ScanStatus.COMPLETED, ScanStatus.FAILED, ScanStatus.CANCELLED}: raise HTTPException(409, "Scan สิ้นสุดแล้ว")
    scan.status, scan.phase = ScanStatus.CANCELLED, "ยกเลิกโดยผู้ใช้"; app.store.update_scan(scan)
    return {"scan_id": scan_id, "status": scan.status}
