# Aegis — Autonomous AI Governance & Security Enforcement Engine

Enterprise B2B control plane that **ingests operational telemetry**, **crosswalks it against live regulatory frameworks**, and **stages merge-ready remediation pull requests**.

The runtime is a three-worker loop:

1. **Worker 1 — `telemetry_sentinel`** continuously catalogs simulated model calls, cross-border data pipelines, and agent transactions, then attaches composite risk metadata.
2. **Worker 2 — `regulatory_crosswalker`** evaluates each event against EU AI Act mandates, GDPR Chapter V transfer limits, and financial-security controls (DORA, PCI DSS, SOX change control, GLBA audit).
3. **Worker 3 — `remediator_engine`** drafts code patches, data-masking configuration, environment-variable locks, and policy-as-code, packaged as structured pull-request payloads.

A unified FastAPI surface exposes ingest, evaluation, and remediation APIs.

```
telemetry event  →  catalog/index  →  rules engine  →  staged PR payload
   Worker 1            Worker 1         Worker 2           Worker 3
```

## Repository layout

```
aegis_core/                 Shared models, in-memory governance store, pipeline, loop runtime
telemetry_sentinel/         Worker 1 — ingest, score, catalog, index
regulatory_crosswalker/     Worker 2 — EU AI Act, GDPR, financial rules engine
remediator_engine/          Worker 3 — patch synthesis and PR builder
acquisition_engine/         Target audit, cryptographic proof-reports, license-locked patches
api/                        FastAPI application and routers
scripts/run_loop.py         CLI entry for the continuous loop
tests/                      Mock/unit coverage for workers and HTTP API
```

## Requirements

- Python 3.9+

## Setup

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
```

## Run the enforcement loop

Single tick (Worker 1 → 2 → 3), then exit:

```bash
python -m aegis_core.runtime --once --seed 7 --batch-size 8
```

Continuous ingestion loop (Ctrl+C to stop):

```bash
python -m aegis_core.runtime --interval 2 --batch-size 8 --seed 7
```

Equivalent:

```bash
python scripts/run_loop.py --once
```

Each tick prints event, violation, and pull-request counts plus the in-memory store totals.

## Run the dashboard (API + UI)

```bash
chmod +x scripts/run_app.sh
./scripts/run_app.sh
```

Or:

```bash
python scripts/run_app.py
```

Open `http://127.0.0.1:8080` for the control-plane UI and `http://127.0.0.1:8080/docs` for OpenAPI.

### Additional acquisition routes

| Method | Path | Purpose |
| --- | --- | --- |
| `GET` | `/acquisition/reports/{report_id}/verify` | Recompute SHA-256 chain + HMAC-SHA256 seal |
| `GET` | `/acquisition/packages/{package_id}` | Fetch a staged package (license omitted) |
| `POST` | `/acquisition/packages/{package_id}/unlock` | Unlock files with the issued license key |

```bash
uvicorn api.app:app --host 0.0.0.0 --port 8080 --reload
```

Open `http://127.0.0.1:8080/docs` for the interactive schema.

### Core endpoints

| Method | Path | Purpose |
| --- | --- | --- |
| `GET` | `/health` | Liveness and store counters |
| `POST` | `/telemetry/ingest` | Ingest one structured telemetry event |
| `POST` | `/telemetry/ingest/batch` | Ingest many events |
| `POST` | `/telemetry/simulate` | Worker 1 only: generate and catalog a simulated batch |
| `GET` | `/telemetry/events` | List cataloged events |
| `POST` | `/evaluations/crosswalk` | Worker 2: evaluate one `event_id` or all pending events |
| `GET` | `/evaluations/violations` | List policy findings |
| `POST` | `/remediations/generate` | Worker 3: stage PRs for open violations |
| `GET` | `/remediations/pull-requests` | Fetch staged remediation PRs |
| `POST` | `/pipeline/tick` | Run the full three-worker loop once |
| `POST` | `/pipeline/ingest` | Run the full loop against caller-supplied events |
| `POST` | `/acquisition/audit` | Simulated domain/API sweep → sealed Compliance Failure Proof-Report |
| `POST` | `/acquisition/package/{report_id}` | Worker 3 extension: executive summary + license-locked patch bundle |
| `POST` | `/acquisition/unlock` | Materialize patch files with an activated enterprise license |
| `GET` | `/acquisition/reports` | List sealed proof-reports |

Example — generate traffic and collect remediations:

```bash
curl -s -X POST "http://127.0.0.1:8080/pipeline/tick?batch_size=8" | python -m json.tool
curl -s "http://127.0.0.1:8080/remediations/pull-requests" | python -m json.tool
```

## Regulatory mapping

| Framework | Representative controls encoded in the rules engine |
| --- | --- |
| **EU AI Act** | Art. 5 prohibited social scoring and real-time remote biometric ID; Art. 12 logging; Art. 14 human oversight for high-risk / Annex III systems; Art. 50 transparency for user-facing models |
| **GDPR** | Arts. 44–46 third-country transfers without adequacy/SCCs; Art. 9 special-category data; Arts. 5/25 minimisation and masking; Art. 32 encryption |
| **Financial security** | PCI DSS cardholder protection; DORA/SOC 2 MFA on privileged agents; SOX §404 / DORA change control; GLBA / PCI DSS 10 audit trails |

Rule modules live in `regulatory_crosswalker/rules/`. Adding a control means implementing `evaluate(event) -> PolicyViolation | None` and registering it in `COMPLIANCE_RULES`.

## Remediation artifacts

Worker 3 emits a `RemediationPullRequest` containing unified diffs for one or more of:

- `.env.compliance` — SCC / residency environment locks
- `config/data_masking.yaml` — field-level tokenisation and hashing
- `app/middleware/ai_transparency.py` — Article 50 disclosure middleware
- `aegis_runtime/human_oversight.py` — high-risk execution gate
- `policy/change_control.rego` — dual-control policy
- `deploy/aegis-security-baseline.yaml` — encryption, MFA, audit baseline
- `config/ai_act_prohibited_flags.json` — kill switches for Art. 5 practices

Critical findings are staged with `merge_ready=false` and `status=awaiting_review`.

## Acquisition engine

`acquisition_engine/` is the enterprise GTM control: it **does not scan, exploit, or connect to the target**. It builds a conservative simulated telemetry estate from a company domain or public API URL, runs that estate through Worker 2, and notarizes the findings.

1. `target_auditor.py` — parse domain/URL, simulate a sweep, crosswalk, project GDPR / EU AI Act / financial statutory exposure, emit an HMAC-SHA256 hash-chained **Compliance Failure Proof-Report**.
2. `pr_generator_extension.py` — extends Worker 3 (`AcquisitionRemediator`) to write a send-ready executive summary and a PBKDF2-sealed same-day patch bundle. File contents unlock only with the issued `AEGIS-ENT-...` license key.

```bash
curl -s -X POST http://127.0.0.1:8080/acquisition/audit \
  -H 'Content-Type: application/json' \
  -d '{"target":"https://api.example.com/v1/chat","annual_turnover_eur":250000000}'
```

## Tests

```bash
pytest -q
```

The suite covers risk scoring, deterministic GDPR/AI Act findings, PR file synthesis, and the FastAPI enforcement path.

## Configuration

Environment variables use the `AEGIS_` prefix (see `.env.example`):

- `AEGIS_LOOP_INTERVAL_SECONDS` — delay between continuous-loop ticks (default `2`)
- `AEGIS_INGEST_BATCH_SIZE` — simulated events per tick (default `8`)
- `AEGIS_HIGH_RISK_THRESHOLD` / `AEGIS_CRITICAL_RISK_THRESHOLD`
- `AEGIS_SIGNING_KEY` — HMAC key for proof-report seals (rotate in production)
- `AEGIS_DEFAULT_TURNOVER_EUR` — assumed worldwide turnover used in fine projections

The current store is process-local and in-memory, which is the correct foundation for the control-plane loop. Swap `GovernanceStore` for Redis/Postgres when you attach durable tenancy.
