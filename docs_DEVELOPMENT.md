# Contributor ownership and request flow

CipherOps is split so page and API work can proceed in parallel. Each workstream owns its listed files; shared contracts should be changed in a coordinated pull request.

## Seven developer workstreams

| Developer | Owns | Typical work |
| --- | --- | --- |
| 1 · App shell | `src/App.tsx`, navigation in `src/shared.ts` | Session restore/expiry, page selection, responsive shell and navigation |
| 2 · SOC dashboard | `src/pages/Dashboard.tsx` | Posture cards, threat map, charts and incident shortcuts |
| 3 · Incident response | `src/pages/Incidents.tsx` | Incident list, assignment/status updates, database activity timeline, notes and approval requests |
| 4 · Security modules | `src/pages/ModulePage.tsx`, `src/pages/AssetsPage.tsx`, `src/pages/AlertsPage.tsx` | Connected security and threat indicator queues, cross-incident automation, compliance/report screens, assets and alert triage |
| 5 · Access and integrations | `src/pages/AdminPage.tsx`, `src/pages/SecuritySettings.tsx`, `src/pages/LoginScreen.tsx`, `src/pages/IntegrationsPage.tsx` | Login/MFA/optional OIDC, users/roles/audit and integration key setup/revocation |
| 6 · Identity API | `backend/app/routers/auth.py`, `backend/app/security.py`, `backend/app/dependencies.py` | Login/MFA, token handling and permission dependencies |
| 7 · Operations and ingestion API | `backend/app/routers/incidents.py`, `backend/app/routers/admin.py`, `backend/app/routers/platform.py`, `backend/app/main.py`, models/schemas/migrations | Governance/workflow/domain APIs, dashboard, alert/asset APIs, telemetry/IOC integrations, administration and persistence |

For a larger team, split workstream 7 between operations routes and admin/platform data. Keep `src/shared.ts`, `backend/app/schemas.py`, `backend/app/models.py`, and database migrations as contract-owned files: propose changes with the affected page/API owner and update both ends together. Avoid concurrent edits to a shared contract or `src/styles.css`; agree on one owner per change.

## Request flow

1. `src/main.tsx` mounts `App`.
2. `App` restores the browser session, renders login until authenticated, then mounts the selected page inside the shared navigation and layout.
3. Pages use `api()` and shared API types/data from `src/shared.ts`. The helper adds the bearer token and sends expired sessions back to the app shell.
4. FastAPI composes route modules in `backend/app/main.py`: `auth`, `incidents`, `admin`, `platform`, `domains`, `workflows`, and `governance`. Threat IOCs submitted with telemetry are matched against the event `observed_indicators` array and attached to resulting alert context. Integration collectors authenticate with source-specific ingestion keys; analyst APIs use user JWTs and RBAC.
5. Route handlers use schemas, SQLAlchemy models and `get_db`; database schema changes belong in Alembic migrations.

## Handoff checklist

- Keep page-specific UI and behavior in its page module; shared visual primitives belong in `src/components/`.
- When changing an API contract, update the backend schema/handler and the consuming frontend page in the same change.
- Run `npm run lint`, `npm run typecheck`, and `npm run build` before handing off frontend work. Backend style/import/schema and migration checks are run from `backend/`; use the documented isolated test setup when explicitly running the test suite.
- Include the owned paths and any contract changes in the pull request summary so parallel contributors can spot overlap early.
