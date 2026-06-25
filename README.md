# CRM Ticket Sorter

A small web service that classifies customer support tickets for a digital finance
company into case type, severity, department, and a one-sentence agent summary —
with automatic escalation flags for phishing and critical cases.

**Approach:** Rules-based (no LLM, no GPU). Classification is done with weighted
keyword/regex matching across English and common Bangla/Banglish phrasing. This is
fully deterministic, has no external dependencies or API keys, and responds in
milliseconds — comfortably inside the 30s/10s runtime limits.

## Endpoints

| Method | Path | Purpose |
|---|---|---|
| GET | `/health` | Health check |
| POST | `/sort-ticket` | Classify a ticket |

### `POST /sort-ticket`

Request:
```json
{
  "ticket_id": "T-001",
  "channel": "app",
  "locale": "en",
  "message": "I sent 5000 taka to a wrong number this morning, please help me get it back"
}
```

Response:
```json
{
  "ticket_id": "T-001",
  "case_type": "wrong_transfer",
  "severity": "high",
  "department": "dispute_resolution",
  "agent_summary": "Customer reports sending 5000 BDT to the wrong recipient and requests recovery.",
  "human_review_required": false,
  "confidence": 0.75
}
```

`channel` and `locale` are optional. If provided, they must be one of the allowed
enum values in the spec (`app|sms|call_center|merchant_portal` and `bn|en|mixed`
respectively) — invalid values return `422`.

## Safety rule

`agent_summary` never asks the customer to share PIN, OTP, password, or full card
number. Summaries are template-generated (never echo the raw customer message
verbatim) and pass through a sanitizing filter as a second line of defense.

## Project layout

```
app/
  main.py        # FastAPI app, request/response schemas, validation
  classifier.py   # rules-based classification engine
tests/
  test_classifier.py   # covers all 5 public sample cases + edge cases
requirements.txt
Dockerfile
```

## Local development

```bash
python -m venv venv
source venv/bin/activate          # Windows: venv\Scripts\activate
pip install -r requirements.txt
uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload
```

Test it:
```bash
curl http://localhost:8000/health

curl -X POST http://localhost:8000/sort-ticket \
  -H "Content-Type: application/json" \
  -d '{"ticket_id":"T-001","message":"I sent 3000 to wrong number"}'
```

Run the test suite:
```bash
pip install pytest httpx
pytest tests/ -v
```

## Deployment runbook (replication instructions)

This service has **no secrets and no external dependencies**, so deployment is the
same everywhere: install requirements, run uvicorn, expose port 8000 (or `$PORT`)
over HTTPS.

### Option A — Docker (recommended, works on any platform: Render/Railway/Fly/EC2)

```bash
docker build -t ticket-sorter .
docker run -p 8000:8000 ticket-sorter
```

### Option B — Render.com (no Dockerfile needed)

1. Push this repo to GitHub.
2. New → Web Service → connect the repo.
3. Build command: `pip install -r requirements.txt`
4. Start command: `uvicorn app.main:app --host 0.0.0.0 --port $PORT`
5. Render provisions HTTPS automatically. `/health` will be live at
   `https://<your-service>.onrender.com/health`.

### Option C — Railway / Fly.io

Same build/start commands as Render. Both platforms auto-detect Python via
`requirements.txt` and provide free HTTPS.
- Railway: `railway up`, then set start command as above in the service settings.
- Fly: `fly launch` (accept Python detection), `fly deploy`. Fly provides HTTPS by default.

### Option D — Bare EC2 / VM

```bash
sudo apt update && sudo apt install -y python3-venv nginx
git clone <this-repo> && cd ticket-sorter
python3 -m venv venv && source venv/bin/activate
pip install -r requirements.txt
uvicorn app.main:app --host 0.0.0.0 --port 8000 &
# Put nginx (or Caddy) in front with a Let's Encrypt cert for HTTPS,
# reverse-proxying to localhost:8000.
```

### Environment variables

None are required. This service uses no API keys and no LLM calls.

## LLM usage

**No.** Fully rules-based — see `app/classifier.py`.
