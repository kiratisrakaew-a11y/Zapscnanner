import json
from pathlib import Path
import yaml
from scanner.parse_report import parse_report
from scanner.run_scan import _bucket, dedupe, count_by_severity

SCANNER = Path(__file__).resolve().parent.parent / "scanner"

def test_spider_scope_is_bounded():
    """Spider must cap depth+children so SPA sites (200 on every path) can't crawl
    unboundedly and OOM the scanner job. Regression guard for the Vercel/Netlify failures."""
    for plan in ("zap_quick.yaml", "zap_standard.yaml"):
        jobs = yaml.safe_load((SCANNER / plan).read_text())["jobs"]
        spider = next(j for j in jobs if j["type"] == "spider")["parameters"]
        assert spider.get("maxDepth"), f"{plan}: spider missing maxDepth"
        assert spider.get("maxChildren"), f"{plan}: spider missing maxChildren"

def test_parse_zap_report(tmp_path):
    report={"site":[{"@name":"https://example.com","alerts":[{"pluginid":"10038","alert":"Content Security Policy Header Not Set","riskdesc":"Medium (Medium)","confidence":"High","desc":"missing","solution":"add it","instances":[{"uri":"https://example.com/","evidence":"none"}]}]}]}
    path=tmp_path/"report.json"; path.write_text(json.dumps(report))
    result=parse_report(path)
    assert result[0]["risk"]=="Medium" and result[0]["owasp_category"]=="A05: Security Misconfiguration"

def test_bucket_maps_informational_to_info():
    assert _bucket("Informational")=="info"
    assert _bucket("High")=="high" and _bucket("Medium")=="medium" and _bucket("Low")=="low"
    assert _bucket("")=="info"

def test_dedupe_and_counts_are_consistent():
    findings=[{"alert_id":"a","risk":"High"},{"alert_id":"a","risk":"High"},
              {"alert_id":"b","risk":"Informational"},{"alert_id":"c","risk":"Low"}]
    deduped=dedupe(findings)
    counts=count_by_severity(deduped)
    assert len(deduped)==3                       # "a" collapsed
    assert sum(counts.values())==len(deduped)    # totals match stored count
    assert counts=={"high":1,"medium":0,"low":1,"info":1}

