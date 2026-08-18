from threading import Lock
from web.models import Finding, Scan


class MemoryStore:
    def __init__(self):
        self.scans: dict[str, Scan] = {}
        self.findings: dict[str, list[Finding]] = {}
        self.audit: list[dict] = []
        self.lock = Lock()

    def create_scan(self, scan: Scan, audit: dict) -> None:
        with self.lock:
            self.scans[scan.scan_id] = scan
            self.findings[scan.scan_id] = []
            self.audit.append(audit)

    def get_scan(self, scan_id: str) -> Scan | None:
        return self.scans.get(scan_id)

    def list_scans(self) -> list[Scan]:
        return sorted(self.scans.values(), key=lambda s: s.created_at, reverse=True)

    def update_scan(self, scan: Scan) -> None:
        self.scans[scan.scan_id] = scan

    def save_findings(self, scan_id: str, findings: list[Finding]) -> None:
        self.findings[scan_id] = findings

    def get_findings(self, scan_id: str) -> list[Finding]:
        return self.findings.get(scan_id, [])

    def active_count(self) -> int:
        terminal = {"COMPLETED", "FAILED", "CANCELLED"}
        return sum(s.status.value not in terminal for s in self.scans.values())


class FirestoreStore(MemoryStore):
    def __init__(self, project: str | None, database: str):
        from google.cloud import firestore
        self.client = firestore.Client(project=project, database=database)

    def create_scan(self, scan: Scan, audit: dict) -> None:
        self.client.collection("scans").document(scan.scan_id).set(scan.model_dump(mode="json"))
        self.client.collection("audit_logs").add(audit)

    def get_scan(self, scan_id: str) -> Scan | None:
        doc = self.client.collection("scans").document(scan_id).get()
        return Scan(**doc.to_dict()) if doc.exists else None

    def list_scans(self) -> list[Scan]:
        query = self.client.collection("scans").order_by("created_at", direction="DESCENDING").limit(100)
        return [Scan(**d.to_dict()) for d in query.stream()]

    def update_scan(self, scan: Scan) -> None:
        self.client.collection("scans").document(scan.scan_id).set(scan.model_dump(mode="json"))

    def save_findings(self, scan_id: str, findings: list[Finding]) -> None:
        batch = self.client.batch()
        parent = self.client.collection("scans").document(scan_id).collection("alerts")
        for finding in findings:
            batch.set(parent.document(finding.alert_id), finding.model_dump())
        batch.commit()

    def get_findings(self, scan_id: str) -> list[Finding]:
        return [Finding(**d.to_dict()) for d in self.client.collection("scans").document(scan_id).collection("alerts").stream()]

    def active_count(self) -> int:
        statuses = ["QUEUED", "STARTING", "DISCOVERING", "PASSIVE_SCAN", "ACTIVE_SCAN", "ANALYZING"]
        return sum(1 for _ in self.client.collection("scans").where("status", "in", statuses).stream())

