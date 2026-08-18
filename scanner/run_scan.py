import json
import os
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path
from google.cloud import firestore
from scanner.parse_report import parse_report

def update(ref, **values): ref.set({**values,"updated_at":datetime.now(timezone.utc).isoformat()}, merge=True)

def main() -> int:
    scan_id, target, scan_type = os.environ["SCAN_ID"], os.environ["TARGET_URL"], os.getenv("SCAN_TYPE", "quick")
    client=firestore.Client(project=os.getenv("GOOGLE_CLOUD_PROJECT")); ref=client.collection("scans").document(scan_id)
    report=Path("/zap/wrk/zap-report.json"); plan=Path(f"/app/scanner/zap_{scan_type}.yaml")
    env={**os.environ,"TARGET_URL":target}
    try:
        update(ref,status="STARTING",started_at=datetime.now(timezone.utc).isoformat(),phase="เริ่ม OWASP ZAP")
        result=subprocess.run(["zap.sh","-cmd","-autorun",str(plan)],env=env,timeout=int(os.getenv("SCAN_TIMEOUT_SECONDS","1800")),check=False)
        if result.returncode not in {0,1,2}: raise RuntimeError(f"ZAP exited with code {result.returncode}")
        update(ref,status="ANALYZING",progress=90,phase="แปลงผลรายงาน")
        findings=parse_report(report); batch=client.batch(); alerts=ref.collection("alerts")
        for item in findings: batch.set(alerts.document(item["alert_id"]),item)
        batch.commit(); counts={k:sum(1 for f in findings if f["risk"].lower()==k) for k in ("high","medium","low","info")}
        score=max(0,100-counts["high"]*20-counts["medium"]*8-counts["low"]*2); risk="HIGH" if counts["high"] else "MEDIUM" if counts["medium"] else "LOW" if counts["low"] else "INFORMATIONAL"
        update(ref,status="COMPLETED",progress=100,phase="ประเมินเสร็จสมบูรณ์",finished_at=datetime.now(timezone.utc).isoformat(),security_score=score,overall_risk=risk,**counts)
        return 0
    except subprocess.TimeoutExpired: update(ref,status="FAILED",error_code="SCAN_TIMEOUT",error_message="การประเมินใช้เวลานานเกินกำหนด"); return 1
    except Exception as exc: update(ref,status="FAILED",error_code="SCANNER_FAILED",error_message="Scanner ไม่สามารถทำงานจนเสร็จได้"); print(str(exc),file=sys.stderr); return 1
if __name__=="__main__": raise SystemExit(main())

