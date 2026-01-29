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

# Suhas risk scoring module (make sure app/scam_detector.py exists)
from .scam_detector import analyze_message, THRESHOLD

load_dotenv()
API_KEY = os.getenv("API_KEY", "")

app = FastAPI(title="Scam Honeypot API", version="0.7")

# In-memory stores (persisted to disk)
SESSIONS: Dict[str, List[Dict[str, Any]]] = {}
INTEL: Dict[str, Dict[str, Any]] = {}     # session_id -> extracted intel
SCORES: Dict[str, int] = {}               # session_id -> total risk score
STAGES: Dict[str, str] = {}               # session_id -> current stage
DATA_FILE = Path("data.json")


def load_data():
    global SESSIONS, INTEL, SCORES, STAGES
    if DATA_FILE.exists():
        try:
            data = json.loads(DATA_FILE.read_text(encoding="utf-8"))
            SESSIONS = data.get("sessions", {}) or {}
            INTEL = data.get("intel", {}) or {}
            SCORES = data.get("scores", {}) or {}
            STAGES = data.get("stages", {}) or {}
        except Exception:
            SESSIONS = {}
            INTEL = {}
            SCORES = {}
            STAGES = {}


def save_data():
    data = {
        "sessions": SESSIONS,
        "intel": INTEL,
        "scores": SCORES,
        "stages": STAGES,
    }
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
    session_id: Optional[str] = None
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

    # Emails
    emails = re.findall(r"\b[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[A-Za-z]{2,}\b", t)
    if emails:
        found["emails"] = emails

    # UPI IDs (name@bank) — filter out emails by ensuring bank part has no dot
    candidates = re.findall(r"\b[a-zA-Z0-9.\-_]{2,}@[a-zA-Z0-9.\-_]{2,}\b", t)
    upis = [c for c in candidates if "." not in c.split("@", 1)[1]]
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

    return found


def compute_stage(intel: Dict[str, Any]) -> str:
    """
    Stage machine (simple + robust):
    1) need_beneficiary_details  -> ask UPI OR account+IFSC
    2) need_link                 -> ask payment link/QR/upi://pay link
    3) need_beneficiary_confirm  -> ask beneficiary name + bank name
    """
    have_upi = bool(intel.get("upi_ids"))
    have_acct = bool(intel.get("account_numbers"))
    have_ifsc = bool(intel.get("ifsc"))
    have_pay_id = have_upi or (have_acct and have_ifsc)

    have_link = bool(intel.get("urls")) or bool(intel.get("upi_links"))

    if not have_pay_id:
        return "need_beneficiary_details"
    if have_pay_id and not have_link:
        return "need_link"
    return "need_beneficiary_confirm"


def agent_reply_for_stage(stage: str, intel: Dict[str, Any]) -> str:
    if stage == "need_beneficiary_details":
        return (
            "I can help verify, but I need the beneficiary details. "
            "Please share the UPI ID (example: name@bank) OR bank account number + IFSC."
        )
    if stage == "need_link":
        return (
            "Thanks. Please send the payment link/QR link you want me to use (or a upi://pay link), "
            "so I can validate it before proceeding."
        )
    # need_beneficiary_confirm
    return (
        "Got it. For final verification, please confirm the beneficiary name and bank name "
        "exactly as shown on your side."
    )


def ensure_defaults(session_id: str) -> Dict[str, Any]:
    """Ensure intel defaults exist for a session."""
    return INTEL.setdefault(
        session_id,
        {
            "urls": [],
            "upi_links": [],
            "upi_ids": [],
            "ifsc": [],
            "account_numbers": [],
            "phones": [],
            "emails": [],
        },
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
    intel = ensure_defaults(session_id)

    # Risk scoring (Suhas module)
    current_total = int(SCORES.get(session_id, 0))
    score_added, evidence, state = analyze_message(payload.message, current_total)
    new_total = current_total + int(score_added)
    SCORES[session_id] = new_total

    # Decide scam/handoff
    keyword_scam = detect_scam(payload.message)
    handoff = new_total >= THRESHOLD
    is_scam = keyword_scam or handoff

    # Store incoming
    history.append({"ts": datetime.utcnow().isoformat(), "from": "scammer", "text": payload.message})

    # Update intel (merge unique)
    new_found = extract_intel(payload.message)
    for k, v in new_found.items():
        existing = set(intel.get(k, []))
        for item in v:
            if item not in existing:
                intel.setdefault(k, []).append(item)
                existing.add(item)

    # Stage machine (only meaningful after scam detected / handoff)
    if is_scam:
        stage = compute_stage(intel)
        STAGES[session_id] = stage
        reply = agent_reply_for_stage(stage, intel)
    else:
        STAGES[session_id] = "passive"
        reply = "Hello. Please share the transaction reference so I can verify your payment."

    # Store reply
    history.append({"ts": datetime.utcnow().isoformat(), "from": "bot", "text": reply})

    # Persist
    save_data()

    return {
        "session_id": session_id,
        "reply": reply,
        "turns": len(history),
        "scam_detected": is_scam,
        "handoff_to_agent": handoff,
        "stage": STAGES.get(session_id, "passive"),
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
        "stage": STAGES.get(session_id, "unknown"),
        "history": SESSIONS.get(session_id, []),
        "intel": INTEL.get(
            session_id,
            {
                "urls": [],
                "upi_links": [],
                "upi_ids": [],
                "ifsc": [],
                "account_numbers": [],
                "phones": [],
                "emails": [],
            },
        ),
        "risk_total_score": int(SCORES.get(session_id, 0)),
        "risk_threshold": int(THRESHOLD),
    }


@app.post("/reset")
def reset_all():
    SESSIONS.clear()
    INTEL.clear()
    SCORES.clear()
    STAGES.clear()
    save_data()
    return {"status": "reset-done"}
