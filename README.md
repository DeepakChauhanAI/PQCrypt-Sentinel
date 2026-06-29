# PQCrypt Sentinel

**Post-Quantum Cryptography Discovery Platform**

PQCrypt Sentinel is an on-premise, air-gap-capable platform for discovering, assessing, and tracking post-quantum cryptography readiness across enterprise estate. It scans TLS/SSH endpoints, parses certificates, classifies PQC algorithm support, and tracks migration progress toward NIST-aligned quantum-safe cryptography.

## Project Documents

- `01-Product-Requirements-Document.md`
- `03-App-Flow-Document.md`
- `06-Implementation-Plan.md`
- `Technical-Architecture-Document.md`
- `05-Backend-Schema-Document.md`
- `Security-and-Access-Document.md`
- `Secure-Development-Baseline.md`
- `04-UI-UX-Design-Brief.md`
- `Frontend-Specification.md`
- `07-Open-Source-Integration-Guide.md`
- `.env.example`
- `.pre-commit-config.yaml`
- `Feature-Ticket-List.md`

## Quick Start

```bash
cp .env.example .env
docker compose up
```

Services:
- API: http://localhost:8000
- Frontend: http://localhost:3000
- PostgreSQL: localhost:5432
- Redis: localhost:6379

## Repository Structure

```
.
├── backend/           # FastAPI application, Celery workers, scanners
├── frontend/          # React + Vite + TypeScript SPA
├── docker/            # Dockerfiles and nginx config
├── docs/              # Architecture and flow documents
└── docker-compose.yml
```
