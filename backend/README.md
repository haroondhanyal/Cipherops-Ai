# CipherOps AI API

FastAPI service with JWT authentication, optional TOTP MFA/OIDC SSO, RBAC, persistent security-domain findings, incident investigation/approval workflows, compliance/reporting, telemetry integrations and asset inventory.

```sh
# From the repository root. Set POSTGRES_PASSWORD in .env first.
cp .env.example .env
docker compose up -d postgres

cd backend
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
cp .env.example .env
# Replace JWT_SECRET with a random secret; match the database password to the root .env.
alembic upgrade head
uvicorn app.main:app --reload
```

The API initializes built-in RBAC roles and permissions after the migration. To load the five fictional demo users, 20 demo incidents, five alerts and five assets, run this in another terminal. It prompts for one password that will be assigned to all demo users; there is no default account/password:

```sh
cd backend
python -m app.seed_demo
```

For a single user, use `python -m app.cli --email analyst@example.com --name "SOC Analyst" --role "SOC Analyst"`; it prompts for a password.

Interactive API docs are available at `http://localhost:8000/docs`. Admin endpoints for user lifecycle, role permissions, integration management, and audit history require `admin:manage`. Users can enroll in TOTP MFA from **Settings → Security settings**; login requires the six digit code after MFA is enabled.

## Signup, profile and password recovery

Set `ALLOW_PUBLIC_SIGNUP=true` to show self-registration. Signup includes all five built-in domain roles with icons. The selected role is stored as a request; new accounts receive `SOC Analyst` permissions until a Security Administrator assigns their approved role in **Users**. Signup captures a profile photo, first/last name, international calling code, mobile number, country and city. Users can edit these fields from **Settings**.

Password reset tokens are random, stored only as hashes, expire after 20 minutes and can be used once. Configure `SMTP_HOST`, `SMTP_PORT`, `SMTP_USERNAME`, `SMTP_PASSWORD`, `SMTP_FROM_EMAIL` and `SMTP_STARTTLS` to deliver recovery links. For local testing without an email server, set `PASSWORD_RESET_DEV_MODE=true` and use a loopback `FRONTEND_URL`; only then will the API return a development reset URL. Keep that flag disabled outside local development. Successful recovery invalidates existing sessions.

## Integrations and telemetry

After the migration, sign in as a Security Administrator and open **Administration → Integrations**. Create one integration per source. Its high-entropy ingestion key is shown once; store it in the source's secret manager. The generated cURL example posts up to 500 normalized events to `POST /api/v1/telemetry/ingest` with `X-Ingestion-Key`. Each event has a source `external_id`, `event_type`, severity, summary, optional timestamp, optional asset, and source-specific `attributes`. Repeated `(integration, external_id)` events update the existing telemetry record; detections create or refresh a deduplicated alert. Asset identifiers upsert the persistent inventory. Revoke a key from the Integrations screen if it is exposed or no longer needed.

Analysts manage alerts in **Operations → Alerts**. They can update status/assignee or promote a detection into an incident. Incident status/owner changes, analyst notes, and response approval requests are kept in the incident activity timeline. Response requests are records for review; this service does not execute containment actions.

Run backend checks with `ruff check app tests alembic` and `pytest` from this directory. Tests use an isolated SQLite database; the application itself is configured for PostgreSQL.

Demo accounts and the explicitly seeded demo incident records are fictional. Dashboard charts use ingested events; the map shows events with source coordinates. Alerts, incidents, telemetry events, integrations, assets, findings, evidence, approvals, compliance controls and report snapshots are persisted in PostgreSQL.


## Route modules

`app/main.py` owns FastAPI configuration, startup RBAC/control/playbook initialization, health/readiness and router composition. Endpoint groups live in `app/routers/auth.py`, `incidents.py`, `admin.py`, `platform.py`, `domains.py`, `workflows.py` and `governance.py`. Shared persistence and authorization remain in `database.py`, `models.py`, `schemas.py`, and `dependencies.py`.

## Security findings, investigation and governance

A normalized telemetry event may include up to 100 findings. Each finding has `domain` (`cloud`, `identity`, `vulnerability`, `agent`, or `threat`), `external_id`, `title`, `severity`, `risk_score`, optional `asset_key`, description and attributes. Ingestion upserts on `(domain, integration source, external_id)`. Findings appear in their corresponding Security screen and can be assigned/triaged at `GET/PATCH /api/v1/findings` with `findings:read` / `findings:manage`. Threat indicators use `attributes.value`, `indicator_type`, and optional confidence/labels. Analysts may add IOCs from the Threat Intelligence screen; feed integrations can submit them as findings.

Incident detail supports evidence references and SHA-256 digests, separate-operator response approval decisions, manual response playbook checklists, and rule-based summaries of related telemetry. The decision APIs enforce that a requester cannot approve their own request. Playbook approval only records a manual checklist; it never calls cloud, identity or endpoint APIs.

Compliance controls for ISO 27001, SOC 2, NIST CSF and CIS v8 are seeded at API startup. Users with `compliance:manage` can update status and attach evidence references. `reports:manage` can save point-in-time executive, incident, asset-risk and compliance report snapshots; readers download snapshots as CSV from `/api/v1/reports/{id}/csv`.

Threat telemetry correlation is exact-value based: include IOC strings in the event `attributes.observed_indicators` array. Matching active indicators are written to the telemetry payload and raise/deduplicate the resulting alert to at least the indicator severity. For dashboard map plotting, include numeric `latitude` and `longitude` in event attributes. For threat indicators, use the normalized IOC value as `external_id`; it is case-folded for exact matching. The integration endpoint is source-neutral, so vendor collectors or feed forwarders can normalize their data into this schema.

The **Automation** screen lists approval-gated playbook runs across incidents. Analysts can request a workflow against an incident; a different user with `response:approve` decides it, and an authorized analyst marks the manual checklist complete. All transitions are audit logged and mirrored to the incident timeline.

Example telemetry payload carrying an IOC and one finding:

```json
{
  "events": [{
    "external_id": "sensor-event-4821",
    "event_type": "network.connection",
    "severity": "Medium",
    "summary": "Outbound connection observed",
    "attributes": {
      "observed_indicators": ["sync-data.example"],
      "latitude": 24.86,
      "longitude": 67.01
    },
    "findings": [{
      "domain": "threat",
      "external_id": "sync-data.example",
      "title": "Known command and control domain",
      "severity": "Critical",
      "risk_score": 96,
      "attributes": {
        "value": "sync-data.example",
        "indicator_type": "domain",
        "confidence": 96
      }
    }]
  }]
}
```

## Optional OIDC single sign-on

Set these in `backend/.env` to enable the company SSO button. The OIDC issuer, redirect URI and client must be configured at the identity provider. Use an HTTPS issuer and a callback URL matching the backend endpoint exactly. Provision the user in CipherOps beforehand; SSO never creates accounts automatically.

```dotenv
OIDC_ISSUER_URL=https://id.example.com/tenant
OIDC_CLIENT_ID=your-client-id
OIDC_CLIENT_SECRET=your-client-secret
OIDC_REDIRECT_URI=http://localhost:8000/api/v1/auth/sso/callback
FRONTEND_URL=http://localhost:5173
```

The flow uses authorization code + PKCE, signed/expiring state, ID-token signature, audience, issuer, nonce and verified-email checks. Users with CipherOps MFA enabled must have the provider assert `mfa` in the ID token `amr` claim. A short-lived hashed, one-use ticket is exchanged by the frontend for the normal CipherOps session. In production, set HTTPS callback/frontend URLs, restrict CORS to the deployed frontend, use a managed secret store, and configure the provider to emit verified email and MFA claims.

## Operations

`GET /health` is a liveness check; `GET /ready` runs a database connectivity check and returns 503 if the database is unavailable. API responses include baseline browser security headers; TLS termination, backups, database connection sizing, monitoring and deployment-specific secret rotation remain platform responsibilities.

Route modules now include `domains.py` (security findings), `workflows.py` (incident collaboration/approvals/playbooks), and `governance.py` (controls/evidence/reports), composed in `app/main.py`.
