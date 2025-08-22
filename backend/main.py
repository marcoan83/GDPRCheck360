from fastapi import FastAPI, BackgroundTasks, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from pydantic import BaseModel, HttpUrl
from typing import Literal, List, Dict, Any
import uuid, time, os
import httpx
from bs4 import BeautifulSoup
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer

app = FastAPI(title="GDPRCheck360 API", version="0.3.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"], allow_credentials=True, allow_methods=["*"], allow_headers=["*"]
)

# ==========================
# MODELS
# ==========================

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

# ==========================
# STORAGE
# ==========================

scans: Dict[str, ScanResult] = {}

# ==========================
# SCAN FUNCTION
# ==========================

async def run_scan(scan_id: str, url: str, depth: str):
    scans[scan_id].status = "running"
    issues: List[Issue] = []
    score = 100

    try:
        async with httpx.AsyncClient(timeout=10) as client:
            resp = await client.get(url)
            html = resp.text
            soup = BeautifulSoup(html, "html.parser")

            # SECURITY HEADERS
            missing_headers = []
            for h in ["Strict-Transport-Security", "Content-Security-Policy",
                      "X-Content-Type-Options", "Referrer-Policy", "Permissions-Policy"]:
                if h not in resp.headers:
                    missing_headers.append(h)
            if missing_headers:
                issues.append(Issue(
                    area="security", severity="low",
                    title="Header di sicurezza mancanti",
                    evidence={"missing": missing_headers},
                    fix_hint="Imposta HSTS, CSP, X-Content-Type-Options, Referrer-Policy, Permissions-Policy."
                ))
                score -= 10

            # PRIVACY POLICY
            if soup.find("a", href=lambda x: x and "privacy" in x.lower()):
                issues.append(Issue(
                    area="policy", severity="medium",
                    title="Informativa privacy trovata ma non validata",
                    evidence={"policy_url": url + "/privacy"},
                    fix_hint="Controlla titolare, finalità, basi giuridiche, tempi, diritti, DPO, trasferimenti."
                ))
                score -= 15

            # CMP / COOKIE BANNER
            if "cookie" in html.lower():
                issues.append(Issue(
                    area="cookies", severity="medium",
                    title="CMP rilevata. Verifica blocco preventivo",
                    evidence={"url": url},
                    fix_hint="Attiva script solo dopo consenso esplicito."
                ))
                score -= 10

        scans[scan_id].issues = issues
        scans[scan_id].score = max(0, score)
        scans[scan_id].status = "done"

    except Exception as e:
        scans[scan_id].status = "error"
        scans[scan_id].issues = [Issue(
            area="security", severity="high",
            title="Errore interno scanner",
            evidence={"error": str(e)},
            fix_hint="Riprova. Se persiste useremo Playwright headless."
        )]
        scans[scan_id].score = 0


# ==========================
# API ENDPOINTS
# ==========================

@app.post("/scan", response_model=ScanResult)
async def start_scan(req: ScanRequest, tasks: BackgroundTasks):
    scan_id = str(uuid.uuid4())
    scans[scan_id] = ScanResult(scan_id=scan_id, status="pending")
    tasks.add_task(run_scan, scan_id, str(req.url), req.depth)
    return scans[scan_id]

@app.get("/scan/{scan_id}", response_model=ScanResult)
async def get_scan(scan_id: str):
    if scan_id not in scans:
        raise HTTPException(status_code=404, detail="Scan not found")
    return scans[scan_id]

@app.get("/report/{scan_id}")
async def get_report(scan_id: str):
    if scan_id not in scans:
        raise HTTPException(status_code=404, detail="Scan not found")
    scan = scans[scan_id]

    if scan.status != "done":
        raise HTTPException(status_code=400, detail="Scan not completed")

    # GENERA PDF
    report_file = f"report_{scan_id}.pdf"
    doc = SimpleDocTemplate(report_file, pagesize=A4)
    styles = getSampleStyleSheet()
    story = []

    story.append(Paragraph("📊 GDPRCheck360 – Report", styles["Title"]))
    story.append(Spacer(1, 20))
    story.append(Paragraph(f"<b>Scan ID:</b> {scan.scan_id}", styles["Normal"]))
    story.append(Paragraph(f"<b>Status:</b> {scan.status}", styles["Normal"]))
    story.append(Paragraph(f"<b>Score:</b> {scan.score}", styles["Normal"]))
    story.append(Spacer(1, 20))

    for issue in scan.issues or []:
        story.append(Paragraph(f"<b>Area:</b> {issue.area}", styles["Heading3"]))
        story.append(Paragraph(f"<b>Gravità:</b> {issue.severity}", styles["Normal"]))
        story.append(Paragraph(f"<b>Titolo:</b> {issue.title}", styles["Normal"]))
        story.append(Paragraph(f"<b>Fix:</b> {issue.fix_hint}", styles["Normal"]))
        story.append(Spacer(1, 10))

    doc.build(story)

    return FileResponse(report_file, media_type="application/pdf", filename=report_file)
