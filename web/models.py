from datetime import datetime, timezone
from enum import StrEnum
from pydantic import BaseModel, Field, HttpUrl


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


class ScanStatus(StrEnum):
    QUEUED = "QUEUED"
    STARTING = "STARTING"
    DISCOVERING = "DISCOVERING"
    PASSIVE_SCAN = "PASSIVE_SCAN"
    ACTIVE_SCAN = "ACTIVE_SCAN"
    ANALYZING = "ANALYZING"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"
    CANCELLED = "CANCELLED"


class ScanCreate(BaseModel):
    target_url: HttpUrl
    scan_type: str = Field(pattern="^(quick|standard)$")
    authorization_confirmed: bool


class Finding(BaseModel):
    alert_id: str
    name: str
    risk: str
    confidence: str = "Medium"
    url: str
    parameter: str = ""
    zap_description: str = ""
    zap_evidence: str = ""
    zap_solution: str = ""
    owasp_category: str = "Not Assessed"
    plain_language_title: str = ""
    plain_language_summary: str = ""
    business_impact: str = ""
    recommended_action: str = ""
    technical_details: str = ""
    technical_reference: str = ""
    ai_available: bool = False


class Scan(BaseModel):
    scan_id: str
    target: str
    scan_type: str
    session_id: str = "unknown"
    status: ScanStatus = ScanStatus.QUEUED
    created_at: str = Field(default_factory=now_iso)
    started_at: str | None = None
    finished_at: str | None = None
    updated_at: str = Field(default_factory=now_iso)
    high: int = 0
    medium: int = 0
    low: int = 0
    info: int = 0
    security_score: int | None = None
    overall_risk: str | None = None
    executive_summary: str | None = None
    error_code: str | None = None
    error_message: str | None = None
    progress: int = 0
    phase: str = "รอคิวประเมิน"
    pages_discovered: int = 0
    endpoints: int = 0
    parameters: int = 0
    current_activity: str = "กำลังเตรียมงาน"
    events: list[dict] = Field(default_factory=list)
