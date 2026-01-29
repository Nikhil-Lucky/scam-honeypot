import os
import re
import uuid
import json
import time
from pathlib import Path
from datetime import datetime
from typing import Dict, List, Any, Optional, Tuple

from dotenv import load_dotenv
from fastapi import FastAPI, Request, Body
from fastapi.responses import JSONResponse
from pydantic import BaseModel

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
# (Keep generous so portal testers that retry won't get stuck)
RATE_LIMIT_RPS = 50.0
RATE_LIMIT_BURST = 200.0
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
OPEN_PATHS = {"/health", "/", "/docs-info"}
OPEN_PREFIXES = ("/docs", "/openapi.json", "/redoc")


@app.middleware("http")
async def api_key_middleware(request: Request, call_next):
    path = request.url.path

    # payload size guard (based on Content-Length when present)
    cl = request.headers.get("content-length")
    if cl and cl.isdigit() and int(cl) > MAX_BODY_BYTES:
        return JSONResponse(status_code=413, content={"error": "Payload too large"})

    # allow safe public paths without key
    if path in OPEN_PATHS or path.startswith(OPEN_PREFIXES):
        return await call_next(request)

    provided = request.headers.get("x-api-key", "")
    if not API_KEY or provided != API_KEY:
        return JSONResponse(status_code=401, content={"error": "Unauthorized"})

    # rate limit only for protected endpoints
    ip = _get_client_ip(request)
    if not _rate_limit_allow(ip):
        return JSONResponse(status_code=429, content={"error": "Too many requests"})

    return await call_next(request)


# ---------------------------
# Models (still used for local/dev)
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


def analyze_risk(message: str, previous_total: int) -> Dict[str, Any]:
    score_increment = 0
    evidence: List[str] = []
    m = (message or "").lower()

    for w in KEYWORDS["high_risk"]:
        if w in m:
            score_increment += 20
            evidence.append(f"High risk keyword: '{w}'")

    for w in KEYWORDS["medium_risk"]:
        if w in m:
            score_increment += 10
            evidence.append(f"Medium risk keyword: '{w}'")

    if re.search(r"\b\d{10}\b", message or ""):
        score_increment += 15
        evidence.append("Pattern match: 10-digit number detected")

    if re.search(r"(https?://|bit\.ly|tinyurl\.com|t\.me|rb\.gy)", m):
        score_increment += 20
        evidence.append("Pattern match: suspicious link detected")

    if re.search(r"\b[a-zA-Z0-9.\-_]{2,}@[a-zA-Z0-9\-_]{2,}\b", message or ""):
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
    found: Dict[str, Any] = {}
    t = text or ""

    urls = re.findall(r"https?://[^\s]+", t, flags=re.IGNORECASE)
    urls = _dedupe([u.rstrip(".,)]}!?;:") for u in urls])
    if urls:
        found["urls"] = urls

    upi_links = re.findall(r"\bupi://pay\?[^\s]+", t, flags=re.IGNORECASE)
    upi_links = _dedupe([u.rstrip(".,)]}!?;:") for u in upi_links])
    if upi_links:
        found["upi_links"] = upi_links

    emails = _dedupe(re.findall(r"\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b", t))
    if emails:
        found["emails"] = emails

    candidates = re.findall(r"\b[a-zA-Z0-9.\-_]{2,}@[a-zA-Z0-9\-_]{2,}\b", t)
    upis: List[str] = []
    for c in candidates:
        bank_part = c.split("@", 1)[1]
        if "." not in bank_part:
            upis.append(c)
    upis = _dedupe(upis)
    if upis:
        found["upi_ids"] = upis

    ifsc = _dedupe(re.findall(r"\b[A-Z]{4}0[A-Z0-9]{6}\b", t.upper()))
    if ifsc:
        found["ifsc"] = ifsc

    candidates = re.findall(r"\b\d{9,18}\b", t)
    accts = _dedupe([c for c in candidates if len(c) != 10])
    if accts:
        found["account_numbers"] = accts

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
# Agent
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
# Helper: base url for /docs-info
# ---------------------------
def _detect_base_url(request: Request) -> str:
    proto = request.headers.get("x-forwarded-proto") or request.url.scheme
    host = request.headers.get("x-forwarded-host") or request.headers.get("host") or request.url.netloc
    return f"{proto}://{host}"


# ---------------------------
# Robust payload parsing (THIS fixes INVALID_REQUEST_BODY)
# ---------------------------
def _extract_message_fields(payload: Any) -> Tuple[Optional[str], str]:
    """
    Accepts many shapes:
    - {"message": "...", "session_id": "..."}
    - {"text": "..."} or {"input": "..."} etc.
    - {} / None  -> message becomes "" (safe)
    - plain string -> treated as message
    """
    if payload is None:
        return None, ""

    if isinstance(payload, str):
        return None, payload

    if isinstance(payload, dict):
        sid = (
            payload.get("session_id")
            or payload.get("sessionId")
            or payload.get("sid")
        )

        msg = (
            payload.get("message")
            or payload.get("text")
            or payload.get("msg")
            or payload.get("input")
            or payload.get("content")
            or ""
        )

        if not isinstance(msg, str):
            try:
                msg = json.dumps(msg, ensure_ascii=False)
            except Exception:
                msg = str(msg)

        return sid, msg

    # unknown type
    return None, str(payload)


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
    base_url = _detect_base_url(request)
    example_request = {
        "session_id": "optional-session-id",
        "message": "KYC expired. Pay to upi://pay?pa=test@upi. https://bit.ly/pay-now."
    }
    curl_body = json.dumps(example_request, ensure_ascii=False)
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
        "sample_powershell": (
            '$headers = @{ "x-api-key" = "<your-api-key>"; "Content-Type"="application/json" }\n'
            f"$body = '{curl_body}'\n"
            f'Invoke-RestMethod -Method POST -Uri "{base_url}/message" -Headers $headers -Body $body'
        ),
        "example_request_body": example_request,
    }


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

    if is_scam:
        reply = agent_reply(stage, intel)
    else:
        reply = "Hello. Please share the transaction reference so I can verify your payment."

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


@app.post("/message")
async def message_endpoint(request: Request, payload: Any = Body(default=None)):
    # If portal sends invalid JSON/empty body, still handle safely
    if payload is None:
        raw = await request.body()
        if raw:
            try:
                payload = json.loads(raw.decode("utf-8", errors="ignore"))
            except Exception:
                payload = raw.decode("utf-8", errors="ignore")

    session_id, msg = _extract_message_fields(payload)
    return _process_message(session_id, msg)


@app.post("/")
async def root_post(request: Request, payload: Any = Body(default=None)):
    # some evaluators POST to base URL
    return await message_endpoint(request, payload)


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
