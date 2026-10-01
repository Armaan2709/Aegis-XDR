# AegisAI XDR — Clean Installation & Setup Guide

This guide provides step-by-step instructions for deploying **AegisAI XDR** from a fresh operating system installation.

---

## 📋 1. System Prerequisites

Ensure the target system satisfies the following hardware and software requirements:

### Hardware Requirements
- **CPU**: 4 Cores (x86_64 architecture)
- **RAM**: 8 GB minimum (16 GB recommended for full Docker Compose stack)
- **Storage**: 20 GB free disk space

### Software Dependencies
- **Operating System**: Linux (Ubuntu 22.04 LTS+, Debian 12+, RHEL 9+) or macOS (13.0+)
- **Python**: Python 3.11+ (`python3 --version`)
- **Node.js**: Node.js 18+ & npm 9+ (`node -v`, `npm -v`)
- **Docker**: Docker Engine 24.0+ & Docker Compose v2.20+ (`docker --version`)

---

## 🚀 2. Step-by-Step Installation Procedure

### Step 1: Clone Repository
```bash
git clone https://github.com/aegisai/aegisai-xdr.git
cd aegisai-xdr
```

### Step 2: Environment Configuration
Copy the template environment file and configure local parameters:
```bash
cp .env.example .env.development
```

For production deployments, create `.env.production` and generate a secure 64-character secret key:
```bash
cp .env.example .env.production
python3 -c "import secrets; print('SECRET_KEY=' + secrets.token_hex(32))" >> .env.production
```

### Step 3: Backend Virtual Environment & Dependencies
```bash
# Create and activate Python virtual environment
python3 -m venv venv
source venv/bin/activate

# Upgrade pip and install dependencies
pip install --upgrade pip
pip install -r backend/pyproject.toml || pip install -e ./backend
```

### Step 4: Frontend Installation
```bash
cd frontend
npm install
cd ..
```

---

## 🐳 3. Database & Service Launch (Docker Compose)

### Launching Infrastructure Services
```bash
# Launch PostgreSQL, Redis, Elasticsearch, Backend, and Frontend containers
docker compose --env-file .env.development up --build -d
```

### Database Migration & Initialization
Apply Alembic migrations to create the database schema:
```bash
cd backend
PYTHONPATH=. python3 -m alembic -c app/db/alembic.ini upgrade head
cd ..
```

---

## 🏥 4. Health Verification & Service Access

Verify that all containerized services are running and responsive:

```bash
# Check container status
docker compose ps

# Test API Liveness Probe
curl -i http://localhost:8000/api/v1/health/liveness

# Test API Readiness Probe (Postgres, Redis, Elasticsearch)
curl -i http://localhost:8000/api/v1/health/readiness
```

### Access Points
- **Frontend SOC Command Center**: `http://localhost:3000`
- **FastAPI Backend REST API**: `http://localhost:8000`
- **Interactive OpenAPI Documentation**: `http://localhost:8000/docs`
- **Synthetic Demo Portal**: `http://localhost:3000/demo`

---

## 👤 5. Default Analyst Authentication

Log in to the frontend command center (`http://localhost:3000/login`) using default development credentials:

- **Username**: `analyst1`
- **Password**: `password123`
- **Assigned Role**: `SOC_ANALYST`

---

## 🧪 6. Executing System Verification Tests

### Running Pytest Test Suite
```bash
# Run security regression suite (23 tests)
python3 -m pytest tests/security -v

# Run integration suite (9 tests)
python3 -m pytest tests/integration -v

# Run complete backend test suite (166 tests)
python3 -m pytest -v
```

### Running Frontend Validation
```bash
cd frontend
node node_modules/typescript/bin/tsc --noEmit
node node_modules/vite/bin/vite.js build
```
