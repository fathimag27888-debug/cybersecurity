# Quantum Cyber Defense — Quick Start

A defensive security operations platform: FastAPI + SQLite backend, React (Vite + Tailwind) frontend, and a **local Llama 3.2:3B model (via Ollama)** that powers threat explanations, the security copilot, and simulation analysis. Everything runs locally — no cloud AI credentials required.

---

## Prerequisites

| Tool | Purpose | Notes |
|---|---|---|
| Python 3.11+ | Backend | This repo's `.venv` uses Python 3.14 |
| Node.js 18+ | Frontend | `npm --version` to check |
| [Ollama](https://ollama.com/download) | Runs `llama3.2:3B` | Must be running on port `11434` |

---

## 1. Install and run the AI model (Ollama)

```bash
# once per machine
ollama pull llama3.2:3B

# start the Ollama service if it isn't already running (usually auto-starts)
ollama serve
```

Verify the model is available:

```bash
curl http://127.0.0.1:11434/api/tags     # should list llama3.2:3B
```

## 2. Configure the environment

```bash
cp .env.example .env
```

`.env` keys:

| Key | Required | Purpose |
|---|---|---|
| `OLLAMA_BASE_URL` | yes | Default `http://127.0.0.1:11434` |
| `OLLAMA_MODEL` | yes | `llama3.2:3B` |
| `SMTP_HOST/PORT/USERNAME/PASSWORD/FROM` | optional | Sends login OTP emails. **Leave unset for local dev** — the OTP is returned directly by the login API instead. |

No API keys are needed for AI features; the model runs on your machine.

## 3. Start the backend (port 8000)

```bash
python -m venv .venv                    # skip if .venv already exists
source .venv/Scripts/activate           # Windows (bash); use .venv/bin/activate on Linux/macOS
pip install -r backend/requirements.txt

.venv/Scripts/python.exe -m uvicorn backend.main:app --host 127.0.0.1 --port 8000 --reload
```

> Always use `--reload` during development: a process started before you edit `backend/` keeps serving the old code (that is what causes "…restart the backend" style errors).

Sanity check: `curl http://127.0.0.1:8000/health` → `{"status":"ok"}`

## 4. Start the frontend (port 5173)

```bash
cd frontend
npm install
npm run dev
```

Open **http://localhost:5173**. Vite proxies `/api/*` to `http://127.0.0.1:8000`.

Production build: `npm run build` (outputs `frontend/dist`).

## 5. Sign in

Seeded demo accounts:

| Role | Email | Password |
|---|---|---|
| Admin | `admin@quantumcyberdefense.demo` | `admin123` |
| Customer | `customer@quantumcyberdefense.demo` | `customer123` |

Login uses a one-time code: with SMTP configured it is emailed; with SMTP unset the API returns `otp_code` in the response (local development mode). New accounts: `POST /api/auth/register` (customer role).

---

## What the Llama 3.2:3B model does

| Feature | Endpoint | Behaviour |
|---|---|---|
| Security copilot | `POST /api/ai/ask` | Answers questions about the current page/telemetry |
| Threat explanations | `POST /api/threats/analyze` | Adds `reason`, `recommended_action`, `remediation_steps` (`ai_enhanced: true`) |
| Simulation analysis | `POST /api/simulations/run` | AI summary attached as `ai_analysis` |
| Model health | `GET /api/ai/status` | `{provider: "Ollama", model: "llama3.2:3B", status: "ready"}` |

Design rules: rule-based detection stays authoritative (risk score/severity/confidence are never changed by the model), telemetry is treated as untrusted data, and **if Ollama or the model is unavailable the app falls back to deterministic rule-based analysis** with a clear status message — nothing breaks.

Local CPU inference takes roughly 5–15 seconds per call.

---

## Tests

```bash
.venv/Scripts/python.exe -m pytest backend/tests -q
# 27 passed
```

(Install pytest first if needed: `pip install pytest`.)

## Project structure

```
cybersecurity/
├── backend/
│   ├── main.py              # FastAPI app, routers
│   ├── llama_service.py     # Ollama / llama3.2:3B integration
│   ├── api/                 # auth, ai, threats, incidents, analytics, simulations, ...
│   ├── detection/ ml/       # rule-based detection + ML scoring
│   ├── database/            # SQLite stores, demo seeding
│   └── tests/               # pytest suite
├── frontend/
│   └── src/App.jsx          # single-page React UI
├── .env.example             # environment template
└── README.md
```

## Troubleshooting

| Symptom | Fix |
|---|---|
| "Gemini rejected the server credential…" or other stale AI errors | The backend process is running old code. Stop it and restart with `--reload` (step 3). The current codebase contains no Gemini references. |
| Copilot says the model is not installed | `ollama pull llama3.2:3B` |
| Copilot says Ollama is not running | `ollama serve` (check `OLLAMA_BASE_URL` in `.env`) |
| AI answers missing but detection works | Expected fallback: rule-based detection stays available; check `/api/ai/status` |
| Port already in use | Backend 8000, frontend 5173, Ollama 11434 — free the port or change it |
| Frontend shows outdated AI labels | Hard-refresh the tab (`Ctrl+Shift+R`) to drop cached JavaScript |
