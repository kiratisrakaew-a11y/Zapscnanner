import json
import os
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path
from google.cloud import firestore
from scanner.parse_report import parse_report

def update(ref, **values): ref.set({**values,"updated_at":datetime.now(timezone.utc).isoformat()}, merge=True)

SEVERITIES = ("high", "medium", "low", "info")

def _bucket(risk):
    r = (risk or "").lower()
    return "high" if r.startswith("high") else "medium" if r.startswith("medium") else "low" if r.startswith("low") else "info"

def dedupe(findings):
    """One entry per alert_id, matching what is stored (batch.set overwrites by id)."""
    return list({f["alert_id"]: f for f in findings}.values())

def count_by_severity(findings):
    counts = {k: 0 for k in SEVERITIES}
    for f in findings: counts[_bucket(f["risk"])] += 1
    return counts

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
        findings=dedupe(parse_report(report)); alerts=ref.collection("alerts")
        for i in range(0, len(findings), 450):          # chunk to stay under Firestore's 500-write batch limit
            batch=client.batch()
            for item in findings[i:i+450]: batch.set(alerts.document(item["alert_id"]),item)
            batch.commit()
        counts=count_by_severity(findings)
        score=max(0,100-counts["high"]*20-counts["medium"]*8-counts["low"]*2); risk="HIGH" if counts["high"] else "MEDIUM" if counts["medium"] else "LOW" if counts["low"] else "INFORMATIONAL"
        update(ref,status="COMPLETED",progress=100,phase="ประเมินเสร็จสมบูรณ์",finished_at=datetime.now(timezone.utc).isoformat(),security_score=score,overall_risk=risk,**counts)
        try:
            email=(ref.get().to_dict() or {}).get("notify_email")
            if email and os.getenv("SMTP_USER") and os.getenv("SMTP_PASSWORD"):
                from scanner import emailer
                followup=emailer.business_days_from(datetime.now(timezone.utc).date(),5)
                subject,html,text=emailer.build_message(target,score,risk,counts,findings,followup)
                emailer.send(os.getenv("SMTP_HOST","smtp.gmail.com"),os.getenv("SMTP_PORT","587"),os.getenv("SMTP_USER"),os.getenv("SMTP_PASSWORD"),os.getenv("SMTP_FROM") or os.getenv("SMTP_USER"),email,subject,html,text,emailer.build_ics(target,followup))
        except Exception as exc:
            print(f"email send failed: {exc}",file=sys.stderr)
        return 0
    except subprocess.TimeoutExpired: update(ref,status="FAILED",error_code="SCAN_TIMEOUT",error_message="การประเมินใช้เวลานานเกินกำหนด"); return 1
    except Exception as exc: update(ref,status="FAILED",error_code="SCANNER_FAILED",error_message="Scanner ไม่สามารถทำงานจนเสร็จได้"); print(str(exc),file=sys.stderr); return 1
if __name__=="__main__": raise SystemExit(main())

