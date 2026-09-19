# Complete Guide: How to Run the Cybersecurity OSINT Platform

This document provides step-by-step instructions to set up, configure, run, test, and troubleshoot the **Cybersecurity OSINT Intelligence Platform** across Windows, Linux, and macOS.

---

## 📋 System Requirements

- **Python**: 3.11 or higher (Python 3.12 / 3.13 / 3.14 supported)
- **Node.js**: 18.x or 20.x LTS
- **npm**: 9.x or higher
- **Git**: Installed and available in your PATH
- **(Optional) Docker & Docker Compose**: For containerized PostgreSQL, Redis, and OpenSearch. If not running, the platform operates seamlessly using its built-in SQLite development database.

---

## ⚡ Option 1: 1-Click Quickstart (Windows)

The platform includes automated launcher scripts located in the root directory:

### Run Everything (Backend + Frontend)
Double-click **`run_all.bat`** or run in PowerShell/CMD:
```bat
.\run_all.bat
```
*This automatically launches the FastAPI Backend (port 8000) and Next.js Web UI (port 3000) in two separate command windows.*

### Run Backend Only
```bat
.\run_backend.bat
```

### Run Frontend Only
```bat
.\run_frontend.bat
```

### Run Full Test Suite
```bat
.\run_tests.bat
```

---

## 🛠️ Option 2: Step-by-Step Manual Setup

If you prefer running services manually or you are on Linux/macOS, follow these steps:

### Step 1: Navigate to Project Root
```bash
cd cyber-osint
```

### Step 2: Configure Environment Variables
Copy the template `.env.example` to create your local `.env`:

**Windows (PowerShell / CMD):**
```powershell
Copy-Item .env.example .env
# Or in CMD:
copy .env.example .env
```

**Linux / macOS:**
```bash
cp .env.example .env
```

*(You can customize API keys now or configure them interactively later in the Web UI at `/secrets`)*.

---

### Step 3: Install Backend Dependencies
Ensure required Python packages are installed:
```bash
pip install fastapi uvicorn httpx sqlalchemy pydantic pyyaml cryptography python-multipart jinja2
```
*(Optionally install `mistralai` for direct Mistral SDK integration; the platform also features native HTTP fallback)*.

---

### Step 4: Install Frontend Dependencies
Navigate to `apps/web` and install Node dependencies:

**Windows (PowerShell / CMD):**
```powershell
cd apps/web
cmd /c npm install
cd ../..
```

**Linux / macOS:**
```bash
cd apps/web
npm install
cd ../..
```

---

### Step 5: Start the Backend Server (Port 8000)

Open a terminal window in `cyber-osint`:

**Windows PowerShell:**
```powershell
$env:PYTHONPATH=".;apps/api"
python -m uvicorn app.main:app --host 127.0.0.1 --port 8000 --reload
```

**Windows CMD:**
```cmd
set PYTHONPATH=.;apps/api
python -m uvicorn app.main:app --host 127.0.0.1 --port 8000 --reload
```

**Linux / macOS (Bash / Zsh):**
```bash
export PYTHONPATH=".:apps/api"
python -m uvicorn app.main:app --host 127.0.0.1 --port 8000 --reload
```

**Verify Backend is Running:**
- Health Check: [http://127.0.0.1:8000/health](http://127.0.0.1:8000/health) → Returns `{"status":"ok",...}`
- Interactive Swagger Docs: [http://127.0.0.1:8000/docs](http://127.0.0.1:8000/docs)
- ReDoc: [http://127.0.0.1:8000/redoc](http://127.0.0.1:8000/redoc)

---

### Step 6: Start the Frontend Web UI (Port 3000)

Open a second terminal window:

**Windows (PowerShell / CMD):**
```powershell
cd apps/web
cmd /c npm run dev
```

**Linux / macOS:**
```bash
cd apps/web
npm run dev
```

**Verify Frontend is Running:**
- Open your browser to: [http://localhost:3000](http://localhost:3000)

---

## 🔑 Option 3: Managing API Keys in the Web UI

You do not need to edit config files manually. The platform includes a dedicated **API Keys & Integrations Vault**:

1. Open your browser and navigate to:
   👉 **[http://localhost:3000/secrets](http://localhost:3000/secrets)**
2. Available configurations:
   - **`MISTRAL_API_KEY`**: Enables Mistral AI intelligence summarization & threat assessment.
   - **`AI_API_KEY`**: Fallback universal LLM key (OpenAI `gpt-4o`, Anthropic, or local Ollama).
   - **`MISTRAL_MODEL`**: Target model (leave as `auto` for dynamic capability detection).
   - **`GITHUB_TOKEN`**: High-rate-limit GitHub Personal Access Token for GHSA vulnerability advisories and exploit PoCs.
   - **`VIDEO_API_KEY`**: YouTube / Multimedia key for DEF CON, Black Hat, and CCC conference talk indexing.
   - **`DATABASE_URL`**: PostgreSQL database connection string.
   - **`REDIS_URL`**: Redis endpoint for sliding-window rate limiting and task queues.
   - **`SEARCH_URL`**: OpenSearch endpoint for hybrid BM25 + vector search.
3. Click **"Test Connection"** on any key to verify it against live upstream servers.
4. Click **"💾 Save & Apply Keys"** to persist your changes directly to `.env` and immediately hot-reload them into memory without restarting servers.

---

## 🧪 Running Verification & Tests

To execute tests and verify all subsystems:

### Run Full Test Suite
```powershell
.\run_tests.bat
# Or manually:
$env:PYTHONPATH=".;apps/api"
python -m unittest discover -s tests -t . -p "test_*.py"
```

### Run Targeted AI & Secret Management Tests
```powershell
$env:PYTHONPATH=".;apps/api"
python -m unittest tests/test_mistral_ai_summarization.py tests/test_stage35_secret_management.py tests/test_stage28_ai_summarization.py
```

### Build & Validate Frontend TypeScript Compilation
```powershell
cd apps/web
cmd /c npm run build
```
*(Generates production builds for all 22 routes with zero TypeScript or hydration errors)*.

---

## 🌐 Platform Port & Service Reference

| Service | Port | Local URL | Description |
|---|---|---|---|
| **Next.js Web UI** | `3000` | [http://localhost:3000](http://localhost:3000) | Main analyst dashboard & threat explorer |
| **API Keys & Vault** | `3000` | [http://localhost:3000/secrets](http://localhost:3000/secrets) | Interactive credential manager & connectivity tester |
| **Intelligence Engine** | `3000` | [http://localhost:3000/intelligence](http://localhost:3000/intelligence) | AI threat intelligence synthesis & executive briefs |
| **CVE & Vulnerabilities** | `3000` | [http://localhost:3000/vulnerabilities](http://localhost:3000/vulnerabilities) | Real-time CISA KEV and NVD vulnerability catalog |
| **FastAPI Backend** | `8000` | [http://127.0.0.1:8000](http://127.0.0.1:8000) | Core REST API gateway |
| **Interactive API Docs** | `8000` | [http://127.0.0.1:8000/docs](http://127.0.0.1:8000/docs) | Swagger UI for exploring all REST endpoints |
| **Health Check** | `8000` | [http://127.0.0.1:8000/health](http://127.0.0.1:8000/health) | Subsystem health status check |
| **PostgreSQL** *(Optional)* | `5432` | `localhost:5432` | Relational database (falls back to SQLite automatically) |
| **Redis** *(Optional)* | `6379` | `localhost:6379` | Cache & sliding window rate limiter |
| **OpenSearch** *(Optional)* | `9200` | `localhost:9200` | Full-text and vector hybrid search engine |

---

## ❓ Troubleshooting & FAQs

### 1. `Port 8000 or 3000 is already in use`
- Identify and terminate the lingering process:
  ```powershell
  # Check port 8000
  Get-NetTCPConnection -LocalPort 8000 -ErrorAction SilentlyContinue | Select-Object OwningProcess
  # Stop the process
  Stop-Process -Id <PID> -Force
  ```
- Or run uvicorn on a different port:
  ```powershell
  python -m uvicorn app.main:app --host 127.0.0.1 --port 8080 --reload
  ```

### 2. PowerShell blocks npm (`npm.ps1 cannot be loaded because running scripts is disabled`)
- Windows PowerShell execution policy restricts running `.ps1` wrapper scripts by default.
- **Solution**: Invoke npm using CMD:
  ```powershell
  cmd /c npm run dev
  # Or:
  cmd /c npm install
  ```

### 3. ModuleNotFoundError: No module named 'app'
- Ensure your `PYTHONPATH` includes both the project root and `apps/api`:
  ```powershell
  $env:PYTHONPATH=".;apps/api"
  ```

### 4. Do I need to install PostgreSQL or Docker to try the project?
- **No.** The platform is pre-configured with a dual database engine. If PostgreSQL is unreachable, it automatically connects to the local development SQLite database (`cyber_osint_dev.db`), allowing full standalone operation with zero external service requirements.
