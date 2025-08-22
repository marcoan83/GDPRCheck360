from fastapi import FastAPI, BackgroundTasks
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, HttpUrl
from typing import Literal, List, Dict, Any
import uuid, time
import httpx
from bs4 import BeautifulSoup

app = FastAPI(title="GDPRCheck360 API", version="0.2")

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

SCANS: Dict[str, ScanResult] = {}

SEC_HEADERS = [
    "Strict-Transport-Security",
    "Content-Security-Policy",
    "X-Content-Type-Options",
    "Referrer-Policy",
    "Permissions-Policy",
]

TRACKER_HINTS = [
    "googletagmanager.com","google-analytics.com","gtag/js",
    "facebook.net","connect.facebook.net","fbq(",
    "hotjar.com","static.hotjar.com","clarity.ms",
    "segment.com","tracker.js","mixpanel.com",
]

CMP_HINTS = [
    "__tcfapi","__cmp","OneTrust","Didomi","Cookiebot","iubenda","Quantcast Choice"
]

@app.get("/healthz")
def healthz():
    return {"status": "ok"}

@app.get("/")
def root():
    return {"status": "ok", "service": "gdprcheck360-api"}

def http_get(url: str) -> httpx.Response:
    with httpx.Client(follow_redirects=True, timeout=15.0, headers={"User-Agent":"GDPRCheck360/0.2"}) as c:
        return c.get(url)

def analyze(url: str) -> List[Issue]:
    issues: List[Issue] = []

    # Normalize URL
    target = url if url.startswith("http") else f"https://{url}"

    # Fetch
    try:
        resp = http_get(target)
    except Exception as e:
        issues.append(Issue(
            area="security", severity="high",
            title="Sito non raggiungibile",
            evidence={"error": str(e), "url": target},
            fix_hint="Verifica DNS, certificato e raggiungibilità dell'host."
        ))
        return issues

    final_url = str(resp.url)
    html = resp.text or ""
    headers = resp.headers

    # HTTPS / redirect
    if not final_url.startswith("https://"):
        issues.append(Issue(
            area="security", severity="high",
            title="Connessione non protetta (HTTPS mancante)",
            evidence={"final_url": final_url},
            fix_hint="Forza HTTPS e redirect 301 da HTTP a HTTPS; configura certificato valido."
        ))

    # Security headers
    missing = [h for h in SEC_HEADERS if h not in headers]
    if missing:
        issues.append(Issue(
            area="security", severity="low",
            title="Header di sicurezza mancanti",
            evidence={"missing": missing},
            fix_hint="Imposta gli header mancanti sul web server o CDN."
        ))

    # Policy link presence
    soup = BeautifulSoup(html, "html.parser")
    candidate = None
    for a in soup.find_all("a", href=True):
        text = (a.get_text() or "").lower()
        href = a["href"].lower()
        if "privacy" in text or "privacy" in href or "privacy-policy" in href:
            candidate = httpx.URL(final_url).join(a["href"]).human_repr()
            break
    if candidate:
        # very light content check
        issues.append(Issue(
            area="policy", severity="medium",
            title="Informativa privacy trovata ma non validata",
            evidence={"policy_url": candidate},
            fix_hint="Verifica che contenga titolare, finalità, basi giuridiche, tempi, diritti, DPO e trasferimenti."
        ))
    else:
        issues.append(Issue(
            area="policy", severity="high",
            title="Informativa privacy non rilevata",
            evidence={"page": final_url},
            fix_hint="Aggiungi un link ben visibile all’informativa privacy nel footer e nelle pagine di raccolta dati."
        ))

    # Trackers + CMP
    found_trackers = [t for t in TRACKER_HINTS if t in html]
    found_cmp = [c for c in CMP_HINTS if c in html]
    if found_trackers:
        if not found_cmp:
            issues.append(Issue(
                area="cookies", severity="high",
                title="Tracker di terze parti senza CMP rilevata",
                evidence={"url": final_url, "found_scripts": found_trackers},
                fix_hint="Integra una CMP TCF 2.2 e blocca preventivamente gli script fino al consenso."
            ))
        else:
            issues.append(Issue(
                area="cookies", severity="medium",
                title="CMP rilevata. Verifica blocco preventivo",
                evidence={"cmp": found_cmp, "found_scripts": found_trackers},
                fix_hint="Assicurati che gli script si attivino solo dopo consenso esplicito."
            ))

    return issues

def compute_score(issues: List[Issue]) -> int:
    score = 100
    for i in issues:
        if i.severity == "high": score -= 20
        elif i.severity == "medium": score -= 10
        else: score -= 3
    return max(0, min(100, score))

def _run_real_scan(scan_id: str, target_url: str, depth: str):
    SCANS[scan_id].status = "running"
    issues = analyze(target_url)
    # depth esteso: placeholder per future scansioni su altre pagine
    time.sleep(0.5)
    SCANS[scan_id].issues = issues
    SCANS[scan_id].score = compute_score(issues)
    SCANS[scan_id].status = "done"

@app.post("/scan", response_model=ScanResult)
def create_scan(req: ScanRequest, bg: BackgroundTasks):
    scan_id = str(uuid.uuid4())
    SCANS[scan_id] = ScanResult(scan_id=scan_id, status="pending")
    bg.add_task(_run_real_scan, scan_id, str(req.url), req.depth)
    return SCANS[scan_id]

@app.get("/scan/{scan_id}", response_model=ScanResult)
def get_scan(scan_id: str):
    return SCANS.get(scan_id) or ScanResult(scan_id=scan_id, status="error")
