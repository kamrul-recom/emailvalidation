# BulkVerify — Bulk Email Validation MVP

Production-ready bulk email validator: CSV/XLS/PDF upload, free pre-filter, local DNS/MX checks, optional ZeroBounce integration for real activity + catch-all detection, Redis/Celery job queue for 100k+ scale.

## Quick start (local)

```bash
python -m venv .venv
.venv\Scripts\activate          # Windows
pip install -r requirements.txt
pip install -r requirements-dev.txt

cp .env.example .env            # edit as needed
python scripts/fetch_disposable_domains.py

# Dev server (in-memory jobs, no Redis required)
set USE_MEMORY_JOBS=true
python app.py
# → http://localhost:8000
```

## Docker (API + Redis + Celery worker)

```bash
cp .env.example .env
docker compose up --build
# API → http://localhost:8000
```

## Architecture

1. **Pre-filter** (`core/prefilter.py`) — `email-validator` syntax/MX + disposable blocklist; skips paid API on hard failures (~10–25% savings).
2. **Domain check** (`core/domain_check.py`) — NS/SOA existence + MX for mail-capable domains; fail-closed on DNS timeout (`domain_status=unknown`, not assumed valid).
3. **Local validator** (`core/validator.py`) — scoring, role/disposable detection; maps domain/mailbox fields to `legitimacy`.
4. **Reacher** (`core/providers/reacher.py`) — optional SMTP RCPT verification via [check-if-email-exists](https://github.com/reacherhq/check-if-email-exists) sidecar; runs only when `domain_active=true`.
5. **ZeroBounce** (`core/providers/zerobounce.py`) — batch API (small jobs) or bulk file API (≥5k); maps `active_in_days` and catch-all status.
6. **Jobs** (`core/jobs.py` + `workers/tasks.py`) — Redis-backed storage; Celery workers for long-running batches.

### Pipeline order

Prefilter → domain DNS → Reacher (if enabled) → ZeroBounce (if enabled and `needs_api_check`).

Dead domains (e.g. `alu@putul.com`) stop at the DNS stage with `domain_status=not_found`, `smtp_status=skipped` — no SMTP or paid API calls.

## Reacher (SMTP mailbox verification)

Reacher runs as a Docker sidecar and needs **outbound port 25** (many residential/cloud networks block it). Use a VPS or SMTP-friendly host for production SMTP checks.

```bash
# docker-compose includes reacher service on port 8080
USE_REACHER=true
REACHER_URL=http://localhost:8080
```

Set `USE_REACHER=false` for local dev without SMTP (DNS-only validation still catches dead domains like `putul.com` when `CHECK_DNS=true`).

### Example: `alu@putul.com`

With DNS enabled, expected result:

```json
{
  "email": "alu@putul.com",
  "domain_pattern_valid": true,
  "domain_exists": false,
  "domain_active": false,
  "domain_status": "not_found",
  "mailbox_exists": null,
  "smtp_status": "skipped",
  "legitimacy": "invalid",
  "needs_api_check": false
}
```

## Environment variables

| Variable | Default | Description |
|----------|---------|-------------|
| `REDIS_URL` | `redis://localhost:6379/0` | Redis for jobs + Celery |
| `USE_MEMORY_JOBS` | `false` | `true` = in-memory jobs (local dev) |
| `USE_PROVIDER` | `false` | Enable ZeroBounce verification |
| `USE_PREFILTER` | `true` | Free pre-filter before paid API |
| `ZEROBOUNCE_API_KEY` | — | ZeroBounce API key (100 free/month) |
| `COST_PER_EMAIL` | `0.0035` | Display estimate ($/email at 100k PAYG) |
| `CHECK_DNS` | `true` | MX/DNS lookups in local stage |
| `USE_REACHER` | `false` | Enable Reacher SMTP mailbox checks |
| `REACHER_URL` | `http://localhost:8080` | Reacher API base URL |
| `REACHER_TIMEOUT_SECONDS` | `30` | Per-email SMTP check timeout |
| `REACHER_MAX_CONCURRENT` | `5` | Parallel Reacher requests |

See [`.env.example`](.env.example) for full list.

## API endpoints

| Method | Path | Description |
|--------|------|-------------|
| POST | `/api/upload` | Upload files → async job |
| POST | `/api/paste` | Paste text → async job |
| POST | `/api/preview` | Parse files, return count + cost estimate |
| POST | `/api/validate` | Sync validate up to 5,000 emails |
| GET | `/api/job/{id}` | Job status |
| GET | `/api/job/{id}/stream` | SSE progress |
| GET | `/api/job/{id}/stats` | Aggregated stats |
| GET | `/api/job/{id}/emails` | Paginated/filtered results (`domain_status`, `mailbox_exists`, `smtp_status`) |
| GET | `/api/job/{id}/export` | CSV export (supports `catch_all`, `domain_status`, `mailbox_exists`) |
| GET | `/api/config` | Formats, cost rate |

## ZeroBounce pricing note

For **100k emails/month**, buy large non-expiring PAYG packs (~$390–490), not the $99/mo subscription (only 10k credits). Develop against the free 100/month tier.

## Tests

```bash
USE_MEMORY_JOBS=true USE_PROVIDER=false USE_REACHER=false CHECK_DNS=false python -m pytest -q
```

## Deploy

- **VPS (recommended for 100k):** Docker Compose on 2 vCPU / 4 GB RAM + nginx reverse proxy.
- **Render:** use [`render.yaml`](render.yaml) with Redis add-on + worker service.
