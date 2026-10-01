# AegisAI XDR — Enterprise Deployment & Operations Guide

This guide details local development setup, hardened production deployment, Docker Compose orchestration, secrets management, and CI/CD validation for **AegisAI XDR**.

---

## 🔑 1. Environment Variable Reference

All settings are configured via environment variables (`backend/app/core/config.py`):

| Variable Name | Default (Development) | Required in Production | Description |
|---------------|-----------------------|------------------------|-------------|
| `ENVIRONMENT` | `development` | **YES (`production`)** | Operational deployment mode |
| `SECRET_KEY` | `dev_super_secret_key_...` | **YES (Secret Manager)** | JWT cryptographic signing key (>=32 chars) |
| `ALGORITHM` | `HS256` | Optional (`RS256`) | Cryptographic algorithm |
| `POSTGRES_SERVER` | `localhost` | **YES** | PostgreSQL hostname |
| `POSTGRES_PORT` | `5432` | Optional | PostgreSQL TCP port |
| `POSTGRES_USER` | `aegis_user` | **YES** | Database username |
| `POSTGRES_PASSWORD` | `aegis_secure_password`| **YES (Secret Manager)** | Database user password |
| `POSTGRES_DB` | `aegis_xdr_db` | Optional | Database name |
| `DATABASE_URL` | `postgresql+asyncpg://...` | **YES** | Async SQLAlchemy connection string |
| `REDIS_HOST` | `localhost` | **YES** | Redis hostname |
| `REDIS_PORT` | `6379` | Optional | Redis TCP port |
| `REDIS_PASSWORD` | `""` | **YES (Secret Manager)** | Redis password |
| `ELASTICSEARCH_HOST` | `localhost` | **YES** | Elasticsearch hostname |
| `ELASTICSEARCH_PORT` | `9200` | Optional | Elasticsearch TCP port |
| `CORS_ORIGINS` | `http://localhost:3000` | **YES (Explicit origins)**| CORS allowed origins (no wildcard `*`) |
| `SOAR_EXECUTION_MODE` | `SAFE_MOCK_EXECUTION` | **ENFORCED** | Enforces safe simulation boundary |

> 🚨 **Production Security Rule**: `config.py` strictly validates production settings at startup. If `ENVIRONMENT=production` and default keys or wildcard CORS origins are detected, the backend process immediately fails startup with a validation `ValueError`.

---

## 🐳 2. Docker Compose Deployment

The root `docker-compose.yml` orchestrates all system containers:

```yaml
services:
  postgres:
    image: postgres:16-alpine
    environment:
      POSTGRES_USER: ${POSTGRES_USER}
      POSTGRES_PASSWORD: ${POSTGRES_PASSWORD}
      POSTGRES_DB: ${POSTGRES_DB}
    healthcheck:
      test: ["CMD-SHELL", "pg_isready -U ${POSTGRES_USER} -d ${POSTGRES_DB}"]
      interval: 5s
      timeout: 5s
      retries: 5

  redis:
    image: redis:7-alpine
    healthcheck:
      test: ["CMD", "redis-cli", "ping"]
      interval: 5s
      timeout: 5s
      retries: 5

  elasticsearch:
    image: docker.elastic.co/elasticsearch/elasticsearch:8.12.0
    environment:
      - discovery.type=single-node
      - xpack.security.enabled=false

  backend:
    build:
      context: ./backend
      dockerfile: Dockerfile
    ports:
      - "8000:8000"
    depends_on:
      postgres:
        condition: service_healthy
      redis:
        condition: service_healthy

  frontend:
    build:
      context: ./frontend
      dockerfile: Dockerfile
    ports:
      - "3000:80"
    depends_on:
      - backend
```

### Launching Environment
```bash
# 1. Copy environment template
cp .env.example .env.production

# 2. Configure production secrets in .env.production
# (SECRET_KEY, POSTGRES_PASSWORD, REDIS_PASSWORD)

# 3. Build and launch containers
docker compose --env-file .env.production up --build -d
```

---

## 🏥 3. Health Monitoring & Probes

The backend exposes three health endpoints (`backend/app/api/v1/health.py`):

1. **Liveness Probe**: `GET /api/v1/health/liveness`
   - Returns `200 OK` (`{"status": "alive"}`) if the FastAPI app process is responsive.
2. **Readiness Probe**: `GET /api/v1/health/readiness`
   - Checks database, Redis, and Elasticsearch connections. Returns `200 OK` if all dependencies are ready, or `503 Service Unavailable` if a critical dependency is down.
3. **Component Health**: `GET /api/v1/health/deps`
   - Returns detailed latency measurements (in ms) for PostgreSQL, Redis, and Elasticsearch.

---

## 🔄 4. Database Migrations & Backup

### Running Migrations
```bash
# Apply pending Alembic migrations
docker compose exec backend alembic upgrade head
```

### Database Backup
```bash
# Trigger database backup script
bash scripts/db_backup.sh
```

---

## 🚀 5. GitHub Actions CI/CD Pipeline

The `.github/workflows/ci.yml` pipeline automates validation on pull requests and pushes:

1. **Backend Validation**:
   - Python syntax compilation (`compileall`).
   - Security regression tests (`pytest tests/security`).
   - Integration tests (`pytest tests/integration`).
   - Full Pytest suite (`pytest`).
2. **Frontend Validation**:
   - Strict TypeScript check (`tsc --noEmit`).
   - Production Vite bundle build (`vite build`).
3. **Container Infrastructure**:
   - Docker Compose configuration validation (`docker compose config`).
