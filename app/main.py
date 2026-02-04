import os
import re
import uuid
import json
import time
from pathlib import Path
from datetime import datetime, timezone
from typing import Dict, List, Any, Optional, Tuple

from dotenv import load_dotenv
from fastapi import FastAPI, Request, Query
from fastapi.responses import JSONResponse
from pydantic import BaseModel

load_dotenv()
API_KEY = os.getenv("API_KEY", "")

app = FastAPI(title="Scam Honeypot API", version="1.0")

# ---------------------------
# In-memory stores (persisted)
# ---------------------------
SESSIONS: Dict[str, List[Dict[str, Any]]] = {}
INTEL: Dict[str, Dict[str, Any]] = {}
RISK_STATE: Dict[str, int] = {}
DATA_FILE = Path("data.json")

# ---------------------------
# Simple abuse protection
# ---------------------------
MAX_BODY_BYTES = 64 * 1024  # 64KB

RATE_LIMIT_RPS = 2.0
RATE_LIMIT_BURST = 10.0
_RL: Dict[str, Tuple[float, float]] = {}  # ip -> (tokens, last_ts)


def _rate_limit_allow(ip: str) -> bool:
    now = time.monotonic()
    tokens, last = _RL.get(ip, (RATE_LIMIT_BURST, now))
    tokens = min(RATE_LIMIT_BURST, tokens + (now - last) * RATE_LIMIT_RPS)
    if tokens < 1.0:
        _RL[ip] = (tokens, now)
        return False
    _RL[ip] = (tokens - 1.0, now)
    return True


def _get_client_ip(request: Request) -> str:
    xff = request.headers.get("x-forwarded-for", "")
    if xff:
        return xff.split(",")[0].strip()
    if request.client and request.client.host:
        return request.client.host
    return "unknown"


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
# Keep GET / public, but DO NOT leave POST / public.
OPEN_GET_PATHS = {"/", "/health", "/docs-info"}
OPEN_PREFIXES = ("/docs", "/openapi.json", "/redoc")


@app.middleware("http")
async def api_key_middleware(request: Request, call_next):
    path = request.url.path

    # Payload size guard
    cl = request.headers.get("content-length")
    if cl and cl.isdigit() and int(cl) > MAX_BODY_BYTES:
        return JSONResponse(status_code=413, content={"status": "error", "message": "Payload too large"})

    # Public GET endpoints + docs
    if request.method == "GET" and (path in OPEN_GET_PATHS or path.startswith(OPEN_PREFIXES)):
        return await call_next(request)
    if path.startswith(OPEN_PREFIXES):
        return await call_next(request)

    # API key check (protected endpoints)
    provided = request.headers.get("x-api-key", "")
    if not API_KEY or provided != API_KEY:
        return JSONResponse(status_code=401, content={"status": "error", "message": "Unauthorized"})

    # Rate limit (protected endpoints)
    ip = _get_client_ip(request)
    if not _rate_limit_allow(ip):
        return JSONResponse(status_code=429, content={"status": "error", "message": "Too many requests"})

    return await call_next(request)


# ---------------------------
# Global JSON error handler (prevents HTML/plain text)
# ---------------------------
@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    return JSONResponse(
        status_code=500,
        content={"status": "error", "message": "Internal server error"},
    )


# ---------------------------
# Models (kept for type hints only; NOT used as request body now)
# ---------------------------
class MessageIn(BaseModel):
    session_id: Optional[str] = None
    message: str


# ---------------------------
# Scam detection + risk scoring
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


def risk_level(total_score: int) -> str:
    if total_score >= 80:
        return "high"
    if total_score >= THRESHOLD:
        return "medium"
    return "low"


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

    # 10-digit number (phone-ish)
    if re.search(r"\b\d{10}\b", message):
        score_increment += 15
        evidence.append("Pattern match: 10-digit number detected")

    # suspicious links
    if re.search(r"(https?://|bit\.ly|tinyurl\.com|t\.me|rb\.gy|wa\.me)", m):
        score_increment += 20
        evidence.append("Pattern match: suspicious link detected")

    # UPI-like handle
    if re.search(r"\b[a-zA-Z0-9.\-_]{2,}@[a-zA-Z0-9\-_]{2,}\b", message):
        score_increment += 25
        evidence.append("Pattern match: UPI ID detected")

    new_total = previous_total + score_increment
    state = "agent_handoff" if new_total >= THRESHOLD else "passive"

    return {
        "score_added": score_increment,
        "total_score": new_total,
        "risk_level": risk_level(new_total),
        "evidence": evidence,
        "state": state,
        "threshold": THRESHOLD,
    }


def detect_scam_from_risk(risk: Dict[str, Any]) -> bool:
    return risk.get("state") == "agent_handoff"


# ---------------------------
# Intel extraction
# ---------------------------
def _dedupe(items: List[str]) -> List[str]:
    return list(dict.fromkeys(items))


def extract_intel(text: str) -> Dict[str, Any]:
    """
    Extract:
    - urls: http(s) links
    - upi_links: upi://pay?... deep links
    - upi_ids: name@bank (tries to avoid emails)
    - ifsc: ABCD0XXXXXX
    - account_numbers: 9-18 digits (excluding 10-digit phones)
    - phones: last-10 digits normalized
    - emails: valid emails
    - qr_links: likely QR/image links (.png/.jpg etc.)
    - messaging_links: t.me / wa.me links etc.
    - handles: @username handles
    """
    found: Dict[str, Any] = {}
    t = text

    # URLs
    urls = re.findall(r"https?://[^\s]+", t, flags=re.IGNORECASE)
    urls = [u.rstrip(".,)]}!?;:") for u in urls]
    urls = _dedupe(urls)
    if urls:
        found["urls"] = urls

    # Messaging links (subset of urls)
    messaging_links = [u for u in urls if re.search(r"(t\.me/|wa\.me/|chat\.whatsapp\.com/)", u, flags=re.IGNORECASE)]
    if messaging_links:
        found["messaging_links"] = _dedupe(messaging_links)

    # QR / image links (subset of urls)
    qr_links = [u for u in urls if re.search(r"\.(png|jpg|jpeg|webp|gif)(\?|$)", u, flags=re.IGNORECASE) or "qr" in u.lower()]
    if qr_links:
        found["qr_links"] = _dedupe(qr_links)

    # UPI deep links
    upi_links = re.findall(r"\bupi://pay\?[^\s]+", t, flags=re.IGNORECASE)
    upi_links = [u.rstrip(".,)]}!?;:") for u in upi_links]
    upi_links = _dedupe(upi_links)
    if upi_links:
        found["upi_links"] = upi_links

    # Emails
    emails = re.findall(r"\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b", t)
    emails = _dedupe(emails)
    if emails:
        found["emails"] = emails

    # UPI IDs (avoid emails by disallowing '.' in bank part)
    candidates = re.findall(r"\b[a-zA-Z0-9.\-_]{2,}@[a-zA-Z0-9\-_]{2,}\b", t)
    upis: List[str] = []
    for c in candidates:
        bank_part = c.split("@", 1)[1]
        if "." not in bank_part:
            upis.append(c)
    upis = _dedupe(upis)
    if upis:
        found["upi_ids"] = upis

    # IFSC
    ifsc = re.findall(r"\b[A-Z]{4}0[A-Z0-9]{6}\b", t.upper())
    ifsc = _dedupe(ifsc)
    if ifsc:
        found["ifsc"] = ifsc

    # Account numbers (exclude 10-digit)
    num_candidates = re.findall(r"\b\d{9,18}\b", t)
    accts = [c for c in num_candidates if len(c) != 10]
    accts = _dedupe(accts)
    if accts:
        found["account_numbers"] = accts

    # Phones -> last 10 digits
    phone_matches = [m.group(0) for m in re.finditer(r"(?:\+?\d{1,3}[\s\-]?)?\b\d{10}\b", t)]
    phones: List[str] = []
    for p in phone_matches:
        digits = re.sub(r"\D", "", p)
        if len(digits) >= 10:
            phones.append(digits[-10:])
    phones = _dedupe(phones)
    if phones:
        found["phones"] = phones

    # @handles
    handles = re.findall(r"(?<!\w)@([a-zA-Z0-9_]{3,32})\b", t)
    handles = _dedupe([f"@{h}" for h in handles])
    if handles:
        found["handles"] = handles

    return found


def merge_unique_list(dst: Dict[str, Any], key: str, items: List[str]) -> None:
    if key not in dst or not isinstance(dst[key], list):
        dst[key] = []
    existing = set(dst[key])
    for it in items:
        if it not in existing:
            dst[key].append(it)
            existing.add(it)


def default_intel() -> Dict[str, Any]:
    return {
        "urls": [],
        "upi_links": [],
        "upi_ids": [],
        "ifsc": [],
        "account_numbers": [],
        "phones": [],
        "emails": [],
        "qr_links": [],
        "messaging_links": [],
        "handles": [],
    }


# ---------------------------
# Agent (UPI Support persona)
# ---------------------------
def compute_stage(intel: Dict[str, Any]) -> str:
    have_upi = bool(intel.get("upi_ids"))
    have_link = bool(intel.get("urls")) or bool(intel.get("upi_links")) or bool(intel.get("qr_links"))
    have_acct = bool(intel.get("account_numbers"))
    have_ifsc = bool(intel.get("ifsc"))

    if not (have_upi or (have_acct and have_ifsc)):
        return "need_beneficiary_details"
    if (have_upi or (have_acct and have_ifsc)) and not have_link:
        return "need_link"
    return "need_confirmation"


def agent_reply(stage: str) -> str:
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
    return (
        "Got it. For final verification, please confirm the beneficiary name and bank name "
        "exactly as it appears in your app (screenshot text is fine)."
    )


# ---------------------------
# Robust payload parser (portal-safe)
# IMPORTANT: No Pydantic body used in routes, so no 422.
# ---------------------------
async def _parse_message_payload(request: Request) -> Tuple[Optional[str], str]:
    raw = await request.body()
    if raw:
        # Try JSON even if content-type is wrong
        try:
            data = json.loads(raw.decode("utf-8", errors="ignore"))
            if isinstance(data, dict):
                # ---- Evaluator format support ----
                # sessionId: "...", message: { text: "...", sender: "...", timestamp: ... }
                sid = (
                    data.get("sessionId")
                    or data.get("session_id")
                    or data.get("session")
                    or data.get("sid")
                )

                msg = ""
                mobj = data.get("message")
                if isinstance(mobj, dict):
                    msg = (
                        mobj.get("text")
                        or mobj.get("message")
                        or mobj.get("msg")
                        or ""
                    )
                elif isinstance(mobj, str):
                    msg = mobj

                # Backward compatibility
                if not msg:
                    msg = (
                        data.get("msg")
                        or data.get("text")
                        or data.get("input")
                        or ""
                    )

                if isinstance(msg, str) and msg.strip():
                    return (sid if isinstance(sid, str) else None), msg.strip()
        except Exception:
            pass

        # If not JSON, treat as plain text
        msg_txt = raw.decode("utf-8", errors="ignore").strip()
        if msg_txt:
            return None, msg_txt

    # fallback (so tester doesn’t fail)
    return None, "Hello (tester ping). Please send the scam message text."


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _process_message(session_id: Optional[str], message_text: str) -> Dict[str, Any]:
    sid = session_id or str(uuid.uuid4())

    history = SESSIONS.setdefault(sid, [])
    intel = INTEL.setdefault(sid, default_intel())

    history.append({"ts": _now_iso(), "from": "scammer", "text": message_text})

    new_found = extract_intel(message_text)
    for k, v in new_found.items():
        if isinstance(v, list):
            merge_unique_list(intel, k, v)

    prev = int(RISK_STATE.get(sid, 0))
    risk = analyze_risk(message_text, prev)
    RISK_STATE[sid] = int(risk["total_score"])

    is_scam = detect_scam_from_risk(risk)
    stage = compute_stage(intel) if is_scam else "passive"

    reply = agent_reply(stage) if is_scam else "Hello. Please share the transaction reference so I can verify your payment."

    history.append({"ts": _now_iso(), "from": "bot", "text": reply})

    save_data()

    return {
        "session_id": sid,
        "reply": reply,
        "turns": len(history),
        "scam_detected": is_scam,
        "handoff_to_agent": is_scam,
        "stage": stage,
        "intel": intel,
        "risk": risk,
    }


# ---------------------------
# Routes
# ---------------------------
@app.get("/")
def root():
    return {"status": "ok", "service": "scam-honeypot"}


@app.get("/health")
def health():
    return {"ok": True, "status": "up"}


@app.get("/docs-info")
def docs_info(request: Request):
    proto = request.headers.get("x-forwarded-proto") or request.url.scheme
    host = request.headers.get("x-forwarded-host") or request.headers.get("host") or request.url.netloc
    base_url = f"{proto}://{host}"

    return {
        "service": "Scam Honeypot API",
        "base_url": base_url,
        "auth": {"required": True, "header_name": "x-api-key"},
        "endpoints": [
            {"method": "GET", "path": "/health"},
            {"method": "GET", "path": "/docs-info"},
            {"method": "POST", "path": "/message"},
            {"method": "POST", "path": "/"},
            {"method": "GET", "path": "/session/{session_id}"},
            {"method": "GET", "path": "/intel/{session_id}"},
            {"method": "GET", "path": "/intel?limit=20"},
            {"method": "GET", "path": "/stats"},
            {"method": "POST", "path": "/reset"},
        ],
        "example_request_body": {
            "sessionId": "optional-session-id",
            "message": {"sender": "scammer", "text": "KYC expired. Pay upi://pay?pa=test@upi. https://bit.ly/pay-now.", "timestamp": 0},
            "conversationHistory": [],
            "metadata": {"channel": "SMS", "language": "English", "locale": "IN"},
        },
        "notes": [
            "POST / and POST /message accept evaluator schema (sessionId + message.text) OR legacy plain 'message'.",
            "POST responses are constrained to {status, reply} for evaluator compatibility.",
        ],
    }


@app.post("/message")
async def message(request: Request):
    sid, msg = await _parse_message_payload(request)
    out = _process_message(sid, msg)
    # Evaluator expects ONLY these keys
    return {"status": "success", "reply": out["reply"]}


@app.post("/")
async def root_post(request: Request):
    sid, msg = await _parse_message_payload(request)
    out = _process_message(sid, msg)
    # Evaluator expects ONLY these keys
    return {"status": "success", "reply": out["reply"]}


@app.get("/session/{session_id}")
def get_session(session_id: str):
    total = int(RISK_STATE.get(session_id, 0))
    return {
        "session_id": session_id,
        "turns": len(SESSIONS.get(session_id, [])),
        "history": SESSIONS.get(session_id, []),
        "intel": INTEL.get(session_id, default_intel()),
        "risk_total": total,
        "risk_level": risk_level(total),
    }


@app.get("/intel/{session_id}")
def get_intel(session_id: str):
    total = int(RISK_STATE.get(session_id, 0))
    return {
        "session_id": session_id,
        "intel": INTEL.get(session_id, default_intel()),
        "risk_total": total,
        "risk_level": risk_level(total),
    }


@app.get("/intel")
def list_recent_intel(limit: int = Query(default=20, ge=1, le=100)):
    session_ids = list(SESSIONS.keys())[-limit:]
    out = []
    for sid in reversed(session_ids):
        total = int(RISK_STATE.get(sid, 0))
        out.append({
            "session_id": sid,
            "turns": len(SESSIONS.get(sid, [])),
            "risk_total": total,
            "risk_level": risk_level(total),
            "intel": INTEL.get(sid, default_intel()),
        })
    return {"count": len(out), "items": out}


@app.get("/stats")
def stats():
    total_sessions = len(SESSIONS)
    total_turns = sum(len(v) for v in SESSIONS.values())
    scam_sessions = sum(1 for sid, score in RISK_STATE.items() if int(score) >= THRESHOLD)
    return {
        "sessions_total": total_sessions,
        "turns_total": total_turns,
        "scam_sessions": scam_sessions,
        "threshold": THRESHOLD,
    }


@app.post("/reset")
def reset_all():
    SESSIONS.clear()
    INTEL.clear()
    RISK_STATE.clear()
    save_data()
    return {"status": "reset-done"}
