import os
import re
import uuid
import json
from pathlib import Path
from datetime import datetime
from typing import Dict, List, Any

from dotenv import load_dotenv
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel

# Suhas risk scoring module
from .scam_detector import analyze_message, THRESHOLD

load_dotenv()
API_KEY = os.getenv("API_KEY", "")

app = FastAPI(title="Scam Honeypot API", version="0.6")

# In-memory stores (persisted to disk)
SESSIONS: Dict[str, List[Dict[str, Any]]] = {}
INTEL: Dict[str, Dict[str, Any]] = {}   # session_id -> extracted intel
SCORES: Dict[str, int] = {}             # session_id -> total risk score
DATA_FILE = Path("data.json")


def load_data():
    global SESSIONS, INTEL, SCORES
    if DATA_FILE.exists():
        try:
            data = json.loads(DATA_FILE.read_text(encoding="utf-8"))
            SESSIONS = data.get("sessions", {}) or {}
            INTEL = data.get("intel", {}) or {}
            SCORES = data.get("scores", {}) or {}
        except Exception:
            SESSIONS = {}
            INTEL = {}
            SCORES = {}


def save_data():
    data = {"sessions": SESSIONS, "intel": INTEL, "scores": SCORES}
    DATA_FILE.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")


# Load persisted state at startup
load_data()


@app.middleware("http")
async def api_key_middleware(request: Request, call_next):
    # Allow health check without API key
    if request.url.path == "/health":
        return await call_next(request)

    provided = request.headers.get("x-api-key", "")
    if not API_KEY or provided != API_KEY:
        return JSONResponse(status_code=401, content={"error": "Unauthorized"})
    return await call_next(request)


class MessageIn(BaseModel):
    session_id: str | None = None
    message: str


def detect_scam(text: str) -> bool:
    t = (text or "").lower()
    keywords = [
        "otp", "one time password", "kyc", "verification", "verify",
        "urgent", "immediately", "limited time",
        "click", "link", "http://", "https://",
        "upi", "bank", "account", "ifsc",
        "won", "prize", "lottery", "gift",
        "refund", "chargeback",
        "customer care", "helpline",
        "instagram support", "whatsapp support",
    ]
    if any(k in t for k in keywords):
        return True
    if re.search(r"(bit\.ly|tinyurl\.com|t\.me|rb\.gy)", t):
        return True
    return False


def extract_intel(text: str) -> Dict[str, Any]:
    """Extract URLs, UPI IDs, IFSC codes, bank account-like numbers, phones, and emails."""
    found: Dict[str, Any] = {}
    t = text or ""

    # URLs (strip trailing punctuation)
    urls = re.findall(r"https?://[^\s]+", t, flags=re.IGNORECASE)
    urls = [u.rstrip(".,)]}!?;:") for u in urls]
    if urls:
        found["urls"] = urls

    # UPI payment deep links (upi://pay?pa=... etc.)
    upi_links = re.findall(r"\bupi://pay\?[^\s]+", t, flags=re.IGNORECASE)
    upi_links = [u.rstrip(".,)]}!?;:") for u in upi_links]
    if upi_links:
        found["upi_links"] = upi_links

    # UPI IDs (name@bank)
    upis = re.findall(r"\b[a-zA-Z0-9.\-_]{2,}@[a-zA-Z]{2,}\b", t)
    if upis:
        found["upi_ids"] = upis

    # IFSC
    ifsc = re.findall(r"\b[A-Z]{4}0[A-Z0-9]{6}\b", t.upper())
    if ifsc:
        found["ifsc"] = ifsc

    # Account-like numbers: 9 to 18 digits
    accts = re.findall(r"\b\d{9,18}\b", t)
    if accts:
        found["account_numbers"] = accts

    # Phone numbers (India-friendly): +91 optional, 10 digits starting 6-9
    phones = re.findall(r"\b(?:\+?91[-\s]?)?[6-9]\d{9}\b", t)
    phones = [p.replace(" ", "").replace("-", "") for p in phones]
    if phones:
        found["phones"] = phones

    # Emails
    emails = re.findall(r"\b[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[A-Za-z]{2,}\b", t)
    if emails:
        found["emails"] = emails

    return found


def agent_reply(history: List[Dict[str, Any]], intel: Dict[str, Any]) -> str:
    """
    Simple multi-turn agent:
    - If no intel yet: ask for UPI id or account+IFSC.
    - If got UPI/acct+ifsc but no link: ask for payment link/QR.
    - If got link: ask for beneficiary name and bank details.
    """
    have_upi = bool(intel.get("upi_ids"))
    have_link = bool(intel.get("urls") or intel.get("upi_links"))
    have_acct = bool(intel.get("account_numbers"))
    have_ifsc = bool(intel.get("ifsc"))

    if not (have_upi or (have_acct and have_ifsc)):
        return (
            "I can help verify, but I need the beneficiary details. "
            "Please share the UPI ID (example: name@bank) OR bank account number + IFSC."
        )

    if (have_upi or (have_acct and have_ifsc)) and not have_link:
        return (
            "Thanks. Please send the payment link/QR link you want me to use, "
            "so I can validate it before proceeding."
        )

    return (
        "Got it. For final verification, please confirm the beneficiary name and bank name "
        "exactly as shown on your side."
    )


@app.get("/")
def root():
    return {"status": "ok", "service": "scam-honeypot"}


@app.post("/")
def root_post(payload: MessageIn):
    return message(payload)


@app.get("/health")
def health():
    return {"status": "ok"}


@app.post("/message")
def message(payload: MessageIn):
    session_id = payload.session_id or str(uuid.uuid4())

    history = SESSIONS.setdefault(session_id, [])
    intel = INTEL.setdefault(
        session_id,
        {"urls": [], "upi_links": [], "upi_ids": [], "ifsc": [], "account_numbers": [], "phones": [], "emails": []}
    )

    # Risk scoring (Suhas module)
    current_total = int(SCORES.get(session_id, 0))
    score_added, evidence, state = analyze_message(payload.message, current_total)
    new_total = current_total + int(score_added)
    SCORES[session_id] = new_total

    # Decide scam/handoff
    is_scam = detect_scam(payload.message) or (new_total >= THRESHOLD)
    handoff = (new_total >= THRESHOLD)

    history.append({"ts": datetime.utcnow().isoformat(), "from": "scammer", "text": payload.message})

    # update intel (merge unique)
    new_found = extract_intel(payload.message)
    for k, v in new_found.items():
        existing = set(intel.get(k, []))
        for item in v:
            if item not in existing:
                intel.setdefault(k, []).append(item)
                existing.add(item)

    # reply
    if handoff or is_scam:
        reply = agent_reply(history, intel)
    else:
        reply = "Hello. Please share the transaction reference so I can verify your payment."

    history.append({"ts": datetime.utcnow().isoformat(), "from": "bot", "text": reply})

    save_data()

    return {
        "session_id": session_id,
        "reply": reply,
        "turns": len(history),
        "scam_detected": is_scam,
        "handoff_to_agent": handoff,
        "intel": intel,
        "risk": {
            "score_added": int(score_added),
            "total_score": int(new_total),
            "evidence": evidence,
            "state": state,
            "threshold": int(THRESHOLD),
        },
    }


@app.get("/session/{session_id}")
def get_session(session_id: str):
    return {
        "session_id": session_id,
        "turns": len(SESSIONS.get(session_id, [])),
        "history": SESSIONS.get(session_id, []),
        "intel": INTEL.get(session_id, {"urls": [], "upi_links": [], "upi_ids": [], "ifsc": [], "account_numbers": [], "phones": [], "emails": []}),
        "risk_total_score": int(SCORES.get(session_id, 0)),
        "risk_threshold": int(THRESHOLD),
    }


@app.post("/reset")
def reset_all():
    SESSIONS.clear()
    INTEL.clear()
    SCORES.clear()
    save_data()
    return {"status": "reset-done"}
