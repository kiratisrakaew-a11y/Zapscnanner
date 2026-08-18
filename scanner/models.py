from dataclasses import dataclass

@dataclass
class ParsedAlert:
    alert_id: str; name: str; risk: str; confidence: str; url: str
    parameter: str = ""; description: str = ""; evidence: str = ""; solution: str = ""; reference: str = ""

