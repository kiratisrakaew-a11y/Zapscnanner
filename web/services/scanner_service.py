import asyncio
import os
from datetime import datetime, timezone
from web.config import Settings
from web.models import Finding, Scan, ScanStatus, now_iso


def _event(message: str) -> dict:
    return {"time": datetime.now(timezone.utc).strftime("%H:%M:%S"), "message": message}


def fake_findings(target: str) -> list[Finding]:
    return [Finding(alert_id="10038-1", name="Content Security Policy Header Not Set", risk="Medium", confidence="High", url=target,
        zap_description="Content Security Policy (CSP) header is not set.", zap_evidence="HTTP response header did not include Content-Security-Policy.",
        zap_solution="Configure a Content Security Policy and test it in report-only mode first.", owasp_category="A05: Security Misconfiguration",
        plain_language_title="ยังไม่มีนโยบายควบคุมเนื้อหาที่ Browser โหลดได้", plain_language_summary="เว็บไซต์ยังไม่ได้กำหนดข้อจำกัดว่า Browser สามารถโหลด Script และเนื้อหาจากแหล่งใดได้บ้าง",
        business_impact="หากมีช่องโหว่อื่นร่วมด้วย ความเสี่ยงต่อ Session และข้อมูลของผู้ใช้งานอาจเพิ่มขึ้น", recommended_action="ให้ทีมพัฒนากำหนด Content Security Policy โดยเริ่มจาก Report-Only Mode",
        technical_details="ZAP ไม่พบ Content-Security-Policy response header", technical_reference="ZAP Alert 10038")]


class ScannerService:
    def __init__(self, store, settings: Settings):
        self.store, self.settings = store, settings

    async def dispatch(self, scan: Scan) -> None:
        if self.settings.app_env == "development" or not self.settings.google_cloud_project:
            asyncio.create_task(self._fake_scan(scan.scan_id))
            return
        from google.cloud import run_v2
        client = run_v2.JobsAsyncClient()
        name = client.job_path(self.settings.google_cloud_project, self.settings.cloud_run_region, self.settings.scanner_job_name)
        override = run_v2.RunJobRequest.Overrides(container_overrides=[run_v2.RunJobRequest.Overrides.ContainerOverride(env=[
            {"name": "SCAN_ID", "value": scan.scan_id}, {"name": "TARGET_URL", "value": scan.target}, {"name": "SCAN_TYPE", "value": scan.scan_type}
        ])])
        await client.run_job(request=run_v2.RunJobRequest(name=name, overrides=override))

    async def _fake_scan(self, scan_id: str) -> None:
        stages = [(ScanStatus.STARTING, 8, "กำลังเริ่ม Scanner"), (ScanStatus.DISCOVERING, 28, "ค้นหา Public Pages"),
                  (ScanStatus.PASSIVE_SCAN, 55, "วิเคราะห์ Response โดยไม่โจมตี"), (ScanStatus.ANALYZING, 86, "จัดหมวดหมู่ผลการตรวจสอบ")]
        scan = self.store.get_scan(scan_id)
        if scan and scan.scan_type == "standard": stages.insert(3, (ScanStatus.ACTIVE_SCAN, 72, "ทดสอบความเสี่ยงเชิงรุก"))
        for status, progress, phase in stages:
            await asyncio.sleep(float(os.getenv("FAKE_SCAN_DELAY", "0.25")))
            scan = self.store.get_scan(scan_id)
            if not scan or scan.status == ScanStatus.CANCELLED: return
            scan.status, scan.progress, scan.phase, scan.updated_at = status, progress, phase, now_iso()
            scan.started_at = scan.started_at or now_iso()
            scan.pages_discovered = max(scan.pages_discovered, progress // 2)
            scan.endpoints, scan.parameters, scan.current_activity = progress // 3, progress // 5, phase
            scan.events.append(_event(phase)); self.store.update_scan(scan)
        findings = fake_findings(scan.target)
        self.store.save_findings(scan_id, findings)
        scan.status, scan.progress, scan.phase, scan.finished_at = ScanStatus.COMPLETED, 100, "ประเมินเสร็จสมบูรณ์", now_iso()
        scan.medium, scan.security_score, scan.overall_risk = 1, 92, "MEDIUM"
        scan.executive_summary = "การประเมินพบประเด็นที่ควรวางแผนแก้ไข 1 รายการ ซึ่งเกี่ยวข้องกับการตั้งค่าการป้องกันบน Browser ไม่พบหลักฐานจากการทดสอบครั้งนี้ว่ามีการเข้าถึงระบบโดยไม่ได้รับอนุญาต"
        scan.events.append(_event("จัดทำรายงานเสร็จสมบูรณ์")); self.store.update_scan(scan)

