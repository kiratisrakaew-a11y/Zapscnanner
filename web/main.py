from contextlib import asynccontextmanager
from pathlib import Path
from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from web.api import health, scans
from web.config import get_settings
from web.services.firestore_service import FirestoreStore, MemoryStore
from web.services.scanner_service import ScannerService

BASE = Path(__file__).parent

@asynccontextmanager
async def lifespan(app: FastAPI):
    settings = get_settings(); app.state.settings = settings
    app.state.store = FirestoreStore(settings.google_cloud_project, settings.firestore_database) if settings.store_backend == "firestore" else MemoryStore()
    app.state.scanner = ScannerService(app.state.store, settings)
    yield

app = FastAPI(title="Aegis ZAP Security Scanner", version="1.0.0", lifespan=lifespan)
app.include_router(health.router); app.include_router(scans.router)
app.mount("/static", StaticFiles(directory=BASE / "static"), name="static")
templates = Jinja2Templates(directory=BASE / "templates")

@app.get("/", response_class=HTMLResponse)
def home(request: Request): return templates.TemplateResponse(request, "index.html")

@app.get("/scans/{scan_id}", response_class=HTMLResponse)
def scanning(request: Request, scan_id: str): return templates.TemplateResponse(request, "scanning.html", {"scan_id": scan_id})

@app.get("/scans/{scan_id}/result", response_class=HTMLResponse)
def result(request: Request, scan_id: str):
    scan = request.app.state.store.get_scan(scan_id)
    if not scan: raise HTTPException(404, "ไม่พบ Scan")
    return templates.TemplateResponse(request, "result.html", {"scan": scan, "findings": request.app.state.store.get_findings(scan_id)})

@app.get("/history", response_class=HTMLResponse)
def history(request: Request): return templates.TemplateResponse(request, "history.html", {"scans": request.app.state.store.list_scans()})

