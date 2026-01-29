import os
import re
import uuid
import json
import time
from pathlib import Path
from datetime import datetime
from typing import Dict, List, Any, Optional, Tuple

from dotenv import load_dotenv
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

load_dotenv()
API_KEY = os.getenv("API_KEY", "")

app = FastAPI(title="Scam Honeypot API", version="0.6")

# In-memory stores (persisted to disk)
SESSIONS: Dict[str, List[Dict[str, Any]]] = {}
INTEL: Dict[str, Dict[str, Any]] = {}   # session_id -> extracted intel
RISK_STATE: Dict[str, int] = {}         # session_id -> rolling risk score
DATA_FILE = Path("data.json")

# ---------------------------
# Simple abuse protection
# ---------------------------
MAX_BODY_BYTES = 64 * 1024  # 64KB

# Token-bucket rate limiter (per IP, in-memory)
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
OPEN_PATHS = {"/health", "/", "/docs-info"}  # public helper endpoints
OPEN_PREFIXES = ("/docs", "/openapi.json", "/redoc")


@app.middleware("http")
async def api_key_middleware(request: Request, call_next):
    path = request.url.path

    # Payload size guard (Content-Length when present)
    cl = request.headers.get("content-length")
    if cl and cl.isdigit() and int(cl) > MAX_BODY_BYTES:
        return JSONResponse(status_code=413, content={"error": "Payload too large"})

    # allow safe public paths without key
    if path in OPEN_PATHS or path.startswith(OPEN_PREFIXES):
        return await call_next(request)

    # API key check
    provided = request.headers.get("x-api-key", "")
    if not API_KEY or provided != API_KEY:
        return JSONResponse(status_code=401, content={"error": "Unauthorized"})

    # rate limit protected routes
    ip = _get_client_ip(request)
    if not _rate_limit_allow(ip):
        return JSONResponse(status_code=429, content={"error": "Too many requests"})

    return await call_next(request)


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

    if re.search(r"\b\d{10}\b", message):
        score_increment += 15
        evidence.append("Pattern match: 10-digit number detected")

    if re.search(r"(https?://|bit\.ly|tinyurl\.com|t\.me|rb\.gy)", m):
        score_increment += 20
        evidence.append("Pattern match: suspicious link detected")

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
    - phones: normalized digits (keep last 10 digits)
    - emails: valid emails
    """
    found: Dict[str, Any] = {}
    t = text

    # URLs
    urls = re.findall(r"https?://[^\s]+", t, flags=re.IGNORECASE)
    urls = _dedupe([u.rstrip(".,)]}!?;:") for u in urls])
    if urls:
        found["urls"] = urls

    # UPI deep links
    upi_links = re.findall(r"\bupi://pay\?[^\s]+", t, flags=re.IGNORECASE)
    upi_links = _dedupe([u.rstrip(".,)]}!?;:") for u in upi_links])
    if upi_links:
        found["upi_links"] = upi_links

    # Emails
    emails = _dedupe(re.findall(r"\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b", t))
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
    ifsc = _dedupe(re.findall(r"\b[A-Z]{4}0[A-Z0-9]{6}\b", t.upper()))
    if ifsc:
        found["ifsc"] = ifsc

    # Account numbers (exclude 10-digit phones)
    num_candidates = re.findall(r"\b\d{9,18}\b", t)
    accts = _dedupe([c for c in num_candidates if len(c) != 10])
    if accts:
        found["account_numbers"] = accts

    # Phones (keep last 10 digits)
    phone_matches = [m.group(0) for m in re.finditer(r"(?:\+?\d{1,3}[\s\-]?)?\b\d{10}\b", t)]
    phones: List[str] = []
    for p in phone_matches:
        digits = re.sub(r"\D", "", p)
        if len(digits) >= 10:
            phones.append(digits[-10:])
    phones = _dedupe(phones)
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
# Robust payload parser (prevents 422 / portal INVALID_REQUEST_BODY)
# ---------------------------
async def _parse_message_payload(request: Request) -> Tuple[Optional[str], str]:
    # 0) Query param fallback (some testers do this)
    qp_msg = request.query_params.get("message") or request.query_params.get("msg") or request.query_params.get("text")
    qp_sid = request.query_params.get("session_id") or request.query_params.get("sid") or request.query_params.get("session")
    if qp_msg:
        return (qp_sid if qp_sid else None), qp_msg

    # 1) Try request.json() (even if content-type is wrong, it might work)
    try:
        data = await request.json()
        if isinstance(data, dict):
            msg = (
                data.get("message")
                or data.get("msg")
                or data.get("text")
                or data.get("input")
                or data.get("prompt")
                or ""
            )
            sid = data.get("session_id") or data.get("session") or data.get("sid")
            if isinstance(msg, str) and msg.strip():
                return (sid if isinstance(sid, str) else None), msg.strip()
    except Exception:
        pass

    # 2) Try form-encoded (some portals submit like this)
    try:
        form = await request.form()
        if form:
            msg = form.get("message") or form.get("msg") or form.get("text") or form.get("input") or ""
            sid = form.get("session_id") or form.get("sid") or None
            if isinstance(msg, str) and msg.strip():
                return (sid if isinstance(sid, str) else None), msg.strip()
    except Exception:
        pass

    # 3) Try raw bytes as JSON or plain text
    raw = await request.body()
    if raw:
        # JSON parse
        try:
            data = json.loads(raw.decode("utf-8", errors="ignore"))
            if isinstance(data, dict):
                msg = (
                    data.get("message")
                    or data.get("msg")
                    or data.get("text")
                    or data.get("input")
                    or data.get("prompt")
                    or ""
                )
                sid = data.get("session_id") or data.get("session") or data.get("sid")
                if isinstance(msg, str) and msg.strip():
                    return (sid if isinstance(sid, str) else None), msg.strip()
        except Exception:
            pass

        # plain text
        txt = raw.decode("utf-8", errors="ignore").strip()
        if txt:
            return None, txt

    # 4) Final fallback (never 422)
    return None, "Hello (tester ping). Please send the scam message text."


def _process_message(session_id: Optional[str], message_text: str) -> Dict[str, Any]:
    sid = session_id or str(uuid.uuid4())

    history = SESSIONS.setdefault(sid, [])
    intel = INTEL.setdefault(
        sid,
        {"urls": [], "upi_links": [], "upi_ids": [], "ifsc": [], "account_numbers": [], "phones": [], "emails": []},
    )

    history.append({"ts": datetime.utcnow().isoformat(), "from": "scammer", "text": message_text})

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
    history.append({"ts": datetime.utcnow().isoformat(), "from": "bot", "text": reply})

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
            {"method": "POST", "path": "/reset"},
        ],
        "example_request_body": {
            "session_id": "optional-session-id",
            "message": "KYC expired. Pay to upi://pay?pa=test@upi. https://bit.ly/pay-now."
        },
    }


@app.post("/message")
async def message(request: Request):
    sid, msg = await _parse_message_payload(request)
    return _process_message(sid, msg)


@app.post("/")
async def root_post(request: Request):
    sid, msg = await _parse_message_payload(request)
    return _process_message(sid, msg)


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
