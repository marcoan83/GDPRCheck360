from fastapi import FastAPI, BackgroundTasks
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, HttpUrl
from typing import Literal, List, Dict, Any
import uuid, time
import httpx
from bs4 import BeautifulSoup

app = FastAPI(title="GDPRCheck360 API", version="0.2.1")

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

CMP_HINTS = ["__tcfapi","__cmp","OneTrust","Didomi","Cookiebot","iubenda","Quantcast Choice"]

@app.get("/healthz")
def healthz():
    return {"status": "ok"}

@app.get("/")
def root():
    return {"status": "ok", "service": "gdprcheck360-api"}

def http_get(url: str) -> httpx.Response:
    transport = httpx.HTTPTransport(retries=1)
    with httpx.Client(
        follow_redirects=True,
        timeout=20.0,
        headers={"User-Agent": "Mozilla/5.0 (GDPRCheck360)"},
        transport=transport,
    ) as c:
        return c.get(url)

def analyze(url: str) -> List[Issue]:
    issues: List[Issue] = []
    target = url if url.startswith("http") else f"https://{url}"

    try:
        resp = http_get(target)
    except Exception as e:
        issues.append(Issue(
            area="security", severity="high",
            title="Sito non raggiungibile",
            evidence={"error": str(e), "url": target},
            fix_hint="Verifica DNS, certificato, WAF o rate limit. Riprova con Playwright in futuro."
        ))
        return issues

    final_url = str(resp.url)
    html = resp.text or ""
    # limita dimensione per parser
    html_small = html[:500_000]
    headers = resp.headers

    if not final_url.startswith("https://"):
        issues.append(Issue(
            area="security", severity="high",
            title="Connessione non protetta (HTTPS mancante)",
            evidence={"final_url": final_url},
            fix_hint="Forza HTTPS e redirect 301; certificato valido."
        ))

    missing = [h for h in SEC_HEADERS if h not in headers]
    if missing:
        issues.append(Issue(
            area="security", severity="low",
            title="Header di sicurezza mancanti",
            evidence={"missing": missing},
            fix_hint="Imposta HSTS, CSP, X-Content-Type-Options, Referrer-Policy, Permissions-Policy."
        ))

    soup = BeautifulSoup(html_small, "html.parser")
    candidate = None
    for a in soup.find_all("a", href=True):
        text = (a.get_text() or "").lower()
        href = a["href"].lower()
        if "privacy" in text or "privacy" in href or "privacy-policy" in href:
            candidate = httpx.URL(final_url).join(a["href"]).human_repr()
            break
    if candidate:
        issues.append(Issue(
            area="policy", severity="medium",
            title="Informativa privacy trovata ma non validata",
            evidence={"policy_url": candidate},
            fix_hint="Controlla titolare, finalità, basi giuridiche, tempi, diritti, DPO, trasferimenti."
        ))
    else:
        issues.append(Issue(
            area="policy", severity="high",
            title="Informativa privacy non rilevata",
            evidence={"page": final_url},
            fix_hint="Aggiungi link privacy nel footer e nei punti di raccolta dati."
        ))

    found_trackers = [t for t in TRACKER_HINTS if t in html_small]
    found_cmp = [c for c in CMP_HINTS if c in html_small]
    if found_trackers:
        if not found_cmp:
            issues.append(Issue(
                area="cookies", severity="high",
                title="Tracker di terze parti senza CMP rilevata",
                evidence={"url": final_url, "found_scripts": found_trackers},
                fix_hint="Integra CMP TCF 2.2 con blocco preventivo."
            ))
        else:
            issues.append(Issue(
                area="cookies", severity="medium",
                title="CMP rilevata. Verifica blocco preventivo",
                evidence={"cmp": found_cmp, "found_scripts": found_trackers},
                fix_hint="Attiva script
