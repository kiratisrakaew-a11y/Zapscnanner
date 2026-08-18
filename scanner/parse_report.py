import hashlib
import json
import re
from pathlib import Path
from scanner.models import ParsedAlert

OWASP_RULES = [(re.compile(r"injection|sql|script|xss", re.I), "A03: Injection"), (re.compile(r"crypt|tls|ssl", re.I), "A02: Cryptographic Failures"), (re.compile(r"header|cookie|configuration|directory", re.I), "A05: Security Misconfiguration"), (re.compile(r"auth|access", re.I), "A01: Broken Access Control")]

def owasp_category(name: str) -> str:
    return next((category for pattern, category in OWASP_RULES if pattern.search(name)), "Not Assessed")

def parse_report(path: str | Path) -> list[dict]:
    data = json.loads(Path(path).read_text(encoding="utf-8")); findings=[]
    for site in data.get("site", []):
        for alert in site.get("alerts", []):
            instances = alert.get("instances") or [{}]
            for instance in instances:
                raw_id = f"{alert.get('pluginid','')}-{instance.get('uri','')}-{instance.get('param','')}"
                finding = ParsedAlert(alert_id=hashlib.sha256(raw_id.encode()).hexdigest()[:20], name=alert.get("alert", "Unknown ZAP Alert"), risk=alert.get("riskdesc", "Informational").split(" ")[0], confidence=alert.get("confidence", "Medium"), url=instance.get("uri", site.get("@name", "")), parameter=instance.get("param", ""), description=alert.get("desc", ""), evidence=instance.get("evidence", ""), solution=alert.get("solution", ""), reference=alert.get("reference", ""))
                findings.append({"alert_id":finding.alert_id,"name":finding.name,"risk":finding.risk,"confidence":finding.confidence,"url":finding.url,"parameter":finding.parameter,"zap_description":finding.description,"zap_evidence":finding.evidence,"zap_solution":finding.solution,"technical_details":finding.description,"technical_reference":finding.reference,"owasp_category":owasp_category(finding.name)})
    return findings

