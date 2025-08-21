from fastapi import FastAPI, BackgroundTasks
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, HttpUrl
from typing import Literal, List, Dict, Any
import uuid
import time

app = FastAPI(title="GDPRCheck360 API", version="0.1")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

class ScanRequest(BaseModel):
    url: HttpUrl
    depth: Literal["quick", "extended"] = "quick"

class Issue(BaseModel):
    area: Literal["cookies", "policy", "forms", "third_parties", "security", "contacts"]
    severity: Literal["high", "medium", "low"]
    title: str
    evidence: Dict[str, Any]
    fix_hint: str

class ScanResult(BaseModel):
    scan_id: str
    status: Literal["pending", "running", "done", "error"]
    score: int | None = None
    issues: List[Issue] | None = None

SCANS: Dict[str, ScanResult] = {}

@app.get("/healthz")
def healthz():
    return {"status": "ok"}

@app.get("/")
def root():
    return {"status": "ok", "service": "gdprcheck360-api"}

def _run_fake_scan(scan_id: str, target_url: str, depth: str):
    SCANS[scan_id].status = "running"
    time.sleep(2)  # simulazione
    issues = [
        Issue(
            area="cookies",
            severity="high",
            title="Nessun blocco preventivo dei tracker",
            evidence={"url": target_url, "found_scripts": ["googletagmanager.com", "facebook.net"]},
            fix_hint="Integra CMP TCF v2.2 e blocca script fino al consenso.",
        ),
        Issue(
            area="policy",
            severity="medium",
            title="Informativa privacy senza basi giuridiche esplicite",
            evidence={"policy_url": f"{target_url.rstrip('/')}/privacy"},
            fix_hint="Aggiungi basi giuridiche per ogni finalità e tempi di conservazione.",
        ),
        Issue(
            area="security",
            severity="low",
            title="Header di sicurezza mancanti",
            evidence={"missing": ["Strict-Transport-Security", "Content-Security-Policy"]},
            fix_hint="Configura HSTS e CSP.",
        ),
    ]
    score = 62 if depth == "quick" else 58
    SCANS[scan_id].issues = issues
    SCANS[scan_id].score = score
    SCANS[scan_id].status = "done"

@app.post("/scan", response_model=ScanResult)
def create_scan(req: ScanRequest, bg: BackgroundTasks):
    scan_id = str(uuid.uuid4())
    SCANS[scan_id] = ScanResult(scan_id=scan_id, status="pending")
    bg.add_task(_run_fake_scan, scan_id, str(req.url), req.depth)
    return SCANS[scan_id]

@app.get("/scan/{scan_id}", response_model=ScanResult)
def get_scan(scan_id: str):
    return SCANS.get(scan_id) or ScanResult(scan_id=scan_id, status="error")
    
