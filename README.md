# Scam Honeypot API (Agentic)

AI-powered honeypot API that detects scam intent, engages scammers to extract intelligence (UPI IDs, links, account numbers, IFSC), and stores session history.

## Run locally

### 1) Create `.env` in project root
Create a file named `.env` (same folder as `requirements.txt`) and add:

```
API_KEY=hackathon-csai-key-2026
```

### 2) Install + start server
```bash
python -m venv .venv
# Windows PowerShell
.\.venv\Scripts\Activate.ps1

pip install -r requirements.txt
uvicorn app.main:app --reload --port 8000
```

Server runs at:
- http://127.0.0.1:8000

## Authentication
All endpoints (except `/health`) require header:
- `x-api-key: hackathon-csai-key-2026`

## Endpoints
- GET `/health` (no key)
- POST `/message` (requires header `x-api-key`)
- GET `/session/{session_id}` (requires header `x-api-key`)
- POST `/reset` (requires header `x-api-key`)

## Test (PowerShell)
```powershell
$headers = @{ "x-api-key" = "hackathon-csai-key-2026" }
Invoke-RestMethod -Method POST -Uri "http://127.0.0.1:8000/message" -Headers $headers -ContentType "application/json" -Body ((@{ message="Urgent KYC pending. Click https://bit.ly/pay" } | ConvertTo-Json))
```

## Persistence
Session history and extracted intel are stored in `data.json` (auto-created).  
Note: `.env` and `data.json` are ignored by git via `.gitignore`.

## Deploy
A `Procfile` is included:
```
web: uvicorn app.main:app --host 0.0.0.0 --port $PORT
```

Set environment variable `API_KEY` on the hosting platform.
