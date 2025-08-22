from fastapi import FastAPI, BackgroundTasks, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from pydantic import BaseModel, HttpUrl
from typing import Literal, List, Dict, Any
import uuid, time, httpx, os
from bs4 import BeautifulSoup

# ReportLab
from reportlab.lib.pagesizes import A4
from reportlab.pdfgen import canvas
from reportlab.lib.units import cm

app = FastAPI(title="GDPRCheck360 API", version="0.3.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"], allow_credentials=True, allow_methods=["*"], allow_headers=["*"]
)

class ScanRequest(BaseModel):
    url: HttpUrl
    depth: Literal["quick", "extended"] = "quick"

class Issue(BaseModel):
    area: Literal["cookies","policy","forms","third_parties","security","contacts"]
    severity: Literal["high","medium","low"]
    title: str
    evidence: Dict[str, Any]
    fix_hint: str

class ScanResult(BaseModel):
    scan_id: str
    status: Literal["pending","running","done","error"]
    score: int | None = None
    issues: List[Issue] | None = None

# 🔹 In-memory scans
scans: Dict[str, ScanResult] = {}

@app.post("/scan/start", response_model=ScanResult)
async def start_scan(req: ScanRequest, background_tasks: BackgroundTasks):
    scan_id = str(uuid.uuid4())
    result = ScanResult(scan_id=scan_id, status="pending")
    scans[scan_id] = result
    background_tasks.add_task(run_scan, scan_id, str(req.url), req.depth)
    return result

async def run_scan(scan_id: str, url: str, depth: str):
    scans[scan_id].status = "running"
    await asyncio.sleep(2)  # simulazione delay

    # Mock results
    scans[scan_id].status = "done"
    scans[scan_id].score = 77
    scans[scan_id].issues = [
        Issue(
            area="security",
            severity="low",
            title="Header di sicurezza mancanti",
            evidence={"missing": ["Content-Security-Policy", "X-Content-Type-Options"]},
            fix_hint="Imposta HSTS, CSP, X-Content-Type-Options, Referrer-Policy, Permissions-Policy."
        ),
        Issue(
            area="policy",
            severity="medium",
            title="Informativa privacy trovata",
            evidence={"found": ["finalita","diritti"], "missing": ["titolare","dpo"]},
            fix_hint="Completa titolare, basi giuridiche, DPO, trasferimenti"
        )
    ]

@app.get("/scan/{scan_id}", response_model=ScanResult)
async def get_scan(scan_id: str):
    if scan_id not in scans:
        raise HTTPException(status_code=404, detail="Scan not found")
    return scans[scan_id]

# 🔹 Generazione PDF report
@app.get("/scan/{scan_id}/report")
async def get_report(scan_id: str):
    if scan_id not in scans:
        raise HTTPException(status_code=404, detail="Scan not found")
    scan = scans[scan_id]

    file_path = f"/tmp/report_{scan_id}.pdf"
    c = canvas.Canvas(file_path, pagesize=A4)
    width, height = A4

    # Titolo
    c.setFont("Helvetica-Bold", 18)
    c.drawString(2*cm, height - 2*cm, f"GDPRCheck360 - Report Scansione")
    c.setFont("Helvetica", 12)
    c.drawString(2*cm, height - 3*cm, f"Scan ID: {scan.scan_id}")
    c.drawString(2*cm, height - 4*cm, f"Stato: {scan.status}")
    if scan.score is not None:
        c.drawString(2*cm, height - 5*cm, f"Punteggio: {scan.score}")

    y = height - 7*cm
    if scan.issues:
        for issue in scan.issues:
            c.setFont("Helvetica-Bold", 12)
            c.drawString(2*cm, y, f"[{issue.severity.upper()}] {issue.title}")
            y -= 0.5*cm
            c.setFont("Helvetica", 10)
            c.drawString(2.5*cm, y, f"Area: {issue.area}")
            y -= 0.5*cm
            c.drawString(2.5*cm, y, f"Fix: {issue.fix_hint}")
            y -= 1*cm
            if y < 3*cm:
                c.showPage()
                y = height - 2*cm

    c.save()
    return FileResponse(file_path, filename=f"gdpr_report_{scan_id}.pdf")
