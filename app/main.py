import os
import re
import uuid
import json
from pathlib import Path
from datetime import datetime
from typing import Dict, List, Any, Optional

from dotenv import load_dotenv
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel

load_dotenv()
API_KEY = os.getenv("API_KEY", "")

app = FastAPI(title="Scam Honeypot API", version="0.5")

# In-memory stores (persisted to disk)
SESSIONS: Dict[str, List[Dict[str, Any]]] = {}
INTEL: Dict[str, Dict[str, Any]] = {}   # session_id -> extracted intel
RISK_STATE: Dict[str, int] = {}         # session_id -> rolling risk score
DATA_FILE = Path("data.json")


# ---------------------------
# Persistence
# ---------------------------
def load_data():
    global SESSIONS, INTEL, RISK_STATE
    if DATA_FILE.exists():
        try:
            data = json.loads(DATA_FILE.read_text(encoding="utf-8"))
            SESSIONS = data.get("sessions", {}) or {}
            INTEL = data.get("intel", {}) or {}
            RISK_STATE = data.get("risk_state", {}) or {}
        except Exception:
            SESSIONS = {}
            INTEL = {}
            RISK_STATE = {}


def save_data():
    data = {"sessions": SESSIONS, "intel": INTEL, "risk_state": RISK_STATE}
    DATA_FILE.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")


load_data()


# ---------------------------
# Security middleware
# ---------------------------
OPEN_PATHS = {"/health", "/"}  # safe public pings
OPEN_PREFIXES = ("/docs", "/openapi.json", "/redoc")


@app.middleware("http")
async def api_key_middleware(request: Request, call_next):
    path = request.url.path

    # allow safe public paths without key
    if path in OPEN_PATHS or path.startswith(OPEN_PREFIXES):
        return await call_next(request)

    provided = request.headers.get("x-api-key", "")
    if not API_KEY or provided != API_KEY:
        return JSONResponse(status_code=401, content={"error": "Unauthorized"})
    return await call_next(request)


# ---------------------------
# Models
# ---------------------------
class MessageIn(BaseModel):
    session_id: Optional[str] = None
    message: str


# ---------------------------
# Scam detection + risk scoring
# (simple + explainable)
# ---------------------------
KEYWORDS = {
    "high_risk": [
        "otp", "cvv", "password", "bank account", "lottery", "winner", "urgent",
        "pay tm", "paytm", "gpay", "phonepe", "kyc", "blocked", "freeze", "suspend",
        "refund", "chargeback", "immediately", "verify", "verification"
    ],
    "medium_risk": [
        "click here", "update", "expired", "sir", "madam", "customer care",
        "helpline", "support", "limited time", "prize", "gift"
    ],
}
THRESHOLD = 50


def analyze_risk(message: str, previous_total: int) -> Dict[str, Any]:
    score_increment = 0
    evidence: List[str] = []
    m = message.lower()

    for w in KEYWORDS["high_risk"]:
        if w in m:
            score_increment += 20
            evidence.append(f"High risk keyword: '{w}'")

    for w in KEYWORDS["medium_risk"]:
        if w in m:
            score_increment += 10
            evidence.append(f"Medium risk keyword: '{w}'")

    # 10-digit phone-ish number
    if re.search(r"\b\d{10}\b", message):
        score_increment += 15
        evidence.append("Pattern match: 10-digit number detected")

    # URL shorteners / links
    if re.search(r"(https?://|bit\.ly|tinyurl\.com|t\.me|rb\.gy)", m):
        score_increment += 20
        evidence.append("Pattern match: suspicious link detected")

    # UPI-like handle
    if re.search(r"\b[a-zA-Z0-9.\-_]{2,}@[a-zA-Z0-9\-_]{2,}\b", message):
        score_increment += 25
        evidence.append("Pattern match: UPI ID detected")

    new_total = previous_total + score_increment
    state = "passive"
    if new_total >= THRESHOLD:
        state = "agent_handoff"

    return {
        "score_added": score_increment,
        "total_score": new_total,
        "evidence": evidence,
        "state": state,
        "threshold": THRESHOLD,
    }


def detect_scam_from_risk(risk: Dict[str, Any]) -> bool:
    return risk.get("state") == "agent_handoff"


# ---------------------------
# Intel extraction
# ---------------------------
def extract_intel(text: str) -> Dict[str, Any]:
    """
    Extract:
    - urls: http(s) links
    - upi_links: upi://pay?... deep links
    - upi_ids: name@bank (tries to avoid emails)
    - ifsc: ABCD0XXXXXX
    - account_numbers: 9-18 digits
    - phones: normalized digits
    - emails: valid emails
    """
    found: Dict[str, Any] = {}
    t = text

    # URLs
    urls = re.findall(r"https?://[^\s]+", t, flags=re.IGNORECASE)
    urls = [u.rstrip(".,)]}!?;:") for u in urls]
    if urls:
        found["urls"] = urls

    # UPI deep links
    upi_links = re.findall(r"\bupi://pay\?[^\s]+", t, flags=re.IGNORECASE)
    upi_links = [u.rstrip(".,)]}!?;:") for u in upi_links]
    if upi_links:
        found["upi_links"] = upi_links

    # Emails
    emails = re.findall(r"\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b", t)
    if emails:
        found["emails"] = emails

    # UPI IDs (avoid emails by disallowing '.' in bank part)
    candidates = re.findall(r"\b[a-zA-Z0-9.\-_]{2,}@[a-zA-Z0-9\-_]{2,}\b", t)
    upis = []
    for c in candidates:
        bank_part = c.split("@", 1)[1]
        if "." not in bank_part:  # emails have domain dots
            upis.append(c)
    if upis:
        found["upi_ids"] = upis

    # IFSC
    ifsc = re.findall(r"\b[A-Z]{4}0[A-Z0-9]{6}\b", t.upper())
    if ifsc:
        found["ifsc"] = ifsc

    # Account-like numbers
    accts = re.findall(r"\b\d{9,18}\b", t)
    if accts:
        found["account_numbers"] = accts

    # Phones (+91 optional, keep digits only)
    phone_candidates = re.findall(r"(?:\+?\d{1,3}[\s\-]?)?\b\d{10}\b", t)
    phones = []
    for p in phone_candidates:
        digits = re.sub(r"\D", "", p)
        if len(digits) >= 10:
            phones.append(digits)
    phones = list(dict.fromkeys(phones))
    if phones:
        found["phones"] = phones

    return found


def merge_unique_list(dst: Dict[str, Any], key: str, items: List[str]) -> None:
    if key not in dst or not isinstance(dst[key], list):
        dst[key] = []
    existing = set(dst[key])
    for it in items:
        if it not in existing:
            dst[key].append(it)
            existing.add(it)


# ---------------------------
# Agent (UPI Support persona)
# ---------------------------
def compute_stage(intel: Dict[str, Any]) -> str:
    have_upi = bool(intel.get("upi_ids"))
    have_link = bool(intel.get("urls")) or bool(intel.get("upi_links"))
    have_acct = bool(intel.get("account_numbers"))
    have_ifsc = bool(intel.get("ifsc"))

    if not (have_upi or (have_acct and have_ifsc)):
        return "need_beneficiary_details"
    if (have_upi or (have_acct and have_ifsc)) and not have_link:
        return "need_link"
    return "need_confirmation"


def agent_reply(stage: str, intel: Dict[str, Any]) -> str:
    # Keep replies short + natural so scammers respond with details.
    if stage == "need_beneficiary_details":
        return (
            "Hello, UPI Support here. To verify the beneficiary, please share the UPI ID "
            "(example: name@bank) OR bank account number + IFSC."
        )

    if stage == "need_link":
        return (
            "Thanks. Now send the payment link/QR link you received (or a upi://pay link) "
            "so I can validate it before you proceed."
        )

    # need_confirmation
    return (
        "Got it. For final verification, please confirm the beneficiary name and bank name "
        "exactly as it appears in your app (screenshot text is fine)."
    )


# ---------------------------
# Routes
# ---------------------------
@app.get("/")
def root():
    # public ping (no key) – does not expose anything sensitive
    return {"status": "ok", "service": "scam-honeypot"}


@app.get("/health")
def health():
    return {"status": "ok"}


@app.post("/message")
def message(payload: MessageIn):
    session_id = payload.session_id or str(uuid.uuid4())

    history = SESSIONS.setdefault(session_id, [])
    intel = INTEL.setdefault(
        session_id,
        {"urls": [], "upi_links": [], "upi_ids": [], "ifsc": [], "account_numbers": [], "phones": [], "emails": []},
    )

    # Save incoming
    history.append({"ts": datetime.utcnow().isoformat(), "from": "scammer", "text": payload.message})

    # Update intel
    new_found = extract_intel(payload.message)
    for k, v in new_found.items():
        if isinstance(v, list):
            merge_unique_list(intel, k, v)

    # Risk scoring (rolling)
    prev = int(RISK_STATE.get(session_id, 0))
    risk = analyze_risk(payload.message, prev)
    RISK_STATE[session_id] = int(risk["total_score"])

    is_scam = detect_scam_from_risk(risk)

    stage = compute_stage(intel) if is_scam else "passive"

    if is_scam:
        reply = agent_reply(stage, intel)
    else:
        reply = "Hello. Please share the transaction reference so I can verify your payment."

    history.append({"ts": datetime.utcnow().isoformat(), "from": "bot", "text": reply})

    save_data()

    return {
        "session_id": session_id,
        "reply": reply,
        "turns": len(history),
        "scam_detected": is_scam,
        "handoff_to_agent": is_scam,
        "stage": stage,
        "intel": intel,
        "risk": risk,
    }


@app.post("/")
def root_post(payload: MessageIn):
    # Some evaluators post to base URL
    return message(payload)


@app.get("/session/{session_id}")
def get_session(session_id: str):
    return {
        "session_id": session_id,
        "turns": len(SESSIONS.get(session_id, [])),
        "history": SESSIONS.get(session_id, []),
        "intel": INTEL.get(
            session_id,
            {"urls": [], "upi_links": [], "upi_ids": [], "ifsc": [], "account_numbers": [], "phones": [], "emails": []},
        ),
        "risk_total": int(RISK_STATE.get(session_id, 0)),
    }


@app.post("/reset")
def reset_all():
    SESSIONS.clear()
    INTEL.clear()
    RISK_STATE.clear()
    save_data()
    return {"status": "reset-done"}
