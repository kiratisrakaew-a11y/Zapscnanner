import json
from scanner.parse_report import parse_report

def test_parse_zap_report(tmp_path):
    report={"site":[{"@name":"https://example.com","alerts":[{"pluginid":"10038","alert":"Content Security Policy Header Not Set","riskdesc":"Medium (Medium)","confidence":"High","desc":"missing","solution":"add it","instances":[{"uri":"https://example.com/","evidence":"none"}]}]}]}
    path=tmp_path/"report.json"; path.write_text(json.dumps(report))
    result=parse_report(path)
    assert result[0]["risk"]=="Medium" and result[0]["owasp_category"]=="A05: Security Misconfiguration"

