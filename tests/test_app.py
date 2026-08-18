import os
os.environ.update(APP_ENV="test", STORE_BACKEND="memory", FAKE_SCAN_DELAY="0.01")
import time
from fastapi.testclient import TestClient
from web.main import app

def test_health():
    with TestClient(app) as client: assert client.get("/health").json()=={"status":"ok"}

def test_authorization_required():
    with TestClient(app) as client:
        response=client.post("/api/scans",json={"target_url":"https://example.com","scan_type":"quick","authorization_confirmed":False})
        assert response.status_code==400

def test_create_and_get_scan():
    with TestClient(app) as client:
        response=client.post("/api/scans",headers={"X-Session-ID":"test-a"},json={"target_url":"https://example.com","scan_type":"quick","authorization_confirmed":True})
        assert response.status_code==202
        scan_id=response.json()["scan_id"]
        assert client.get(f"/api/scans/{scan_id}").json()["target"]=="https://example.com/"

def test_findings_enrichment_wired():
    with TestClient(app) as client:
        app.state.ai.enrich=lambda finding: finding.model_copy(update={"plain_language_title":"AI-WIRED","ai_available":True})
        response=client.post("/api/scans",headers={"X-Session-ID":"test-ai"},json={"target_url":"https://example.com","scan_type":"quick","authorization_confirmed":True})
        assert response.status_code==202
        scan_id=response.json()["scan_id"]
        findings=[]
        for _ in range(200):
            if client.get(f"/api/scans/{scan_id}").json()["status"]=="COMPLETED":
                findings=client.get(f"/api/scans/{scan_id}/findings").json()
                break
            time.sleep(0.02)
        assert findings, "scan did not complete or produced no findings"
        assert findings[0]["plain_language_title"]=="AI-WIRED"
        assert findings[0]["ai_available"] is True

