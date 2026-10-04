from contextlib import asynccontextmanager

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from sqlalchemy import select, text
from starlette.middleware.base import BaseHTTPMiddleware

from .config import settings
from .database import SessionLocal
from .models import ComplianceControl, Permission, ResponsePlaybook, Role
from .routers import admin, auth, domains, governance, incidents, platform, search, workflows


class OperationalHeadersMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        response = await call_next(request)
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
        if request.url.path.startswith("/api/"):
            response.headers["Cache-Control"] = "no-store"
        return response


@asynccontextmanager
async def lifespan(_: FastAPI):
    with SessionLocal() as db:
        for key, description in [
            ("dashboard:read", "View security overview"),
            ("incidents:read", "View incidents"),
            ("incidents:manage", "Assign and update incidents"),
            ("alerts:read", "View and triage alerts"),
            ("alerts:manage", "Manage alerts"),
            ("assets:read", "View asset inventory"),
            ("findings:read", "View security domain findings"),
            ("findings:manage", "Triage security domain findings"),
            ("response:approve", "Approve sensitive incident response requests"),
            ("compliance:read", "View compliance controls and evidence"),
            ("compliance:manage", "Update controls and attach evidence"),
            ("reports:read", "View saved security reports"),
            ("reports:manage", "Generate and save security reports"),
            ("admin:manage", "Manage users and roles"),
        ]:
            permission = db.scalar(select(Permission).where(Permission.key == key))
            if permission is None:
                db.add(Permission(key=key, description=description))
        db.flush()
        role_permissions = {
            "SOC Analyst": [
                "dashboard:read",
                "incidents:read",
                "incidents:manage",
                "alerts:read",
                "alerts:manage",
                "assets:read",
                "findings:read",
                "findings:manage",
            ],
            "Security Administrator": [
                "dashboard:read",
                "incidents:read",
                "incidents:manage",
                "alerts:read",
                "alerts:manage",
                "assets:read",
                "findings:read",
                "findings:manage",
                "response:approve",
                "compliance:read",
                "compliance:manage",
                "reports:read",
                "reports:manage",
                "admin:manage",
            ],
            "CISO": [
                "dashboard:read",
                "incidents:read",
                "alerts:read",
                "assets:read",
                "findings:read",
                "response:approve",
                "compliance:read",
                "reports:read",
            ],
            "Cloud Security Engineer": [
                "dashboard:read",
                "incidents:read",
                "alerts:read",
                "assets:read",
                "findings:read",
                "findings:manage",
            ],
            "Compliance Officer": [
                "dashboard:read",
                "incidents:read",
                "alerts:read",
                "assets:read",
                "findings:read",
                "compliance:read",
                "compliance:manage",
                "reports:read",
                "reports:manage",
            ],
        }
        for name, permission_keys in role_permissions.items():
            role = db.scalar(select(Role).where(Role.name == name))
            if role is None:
                role = Role(name=name, description=f"CipherOps {name} role")
                db.add(role)
            role.permissions = list(
                db.scalars(select(Permission).where(Permission.key.in_(permission_keys)))
            )
        for key, name, description, steps in [
            (
                "cloud_exposure",
                "Cloud data exposure review",
                "Review and contain a suspected public cloud resource exposure.",
                [
                    "Confirm the affected resource and business owner",
                    "Preserve provider audit evidence",
                    "Request approval before changing access policy",
                    "Record the verified remediation and follow-up scan",
                ],
            ),
            (
                "identity_compromise",
                "Identity compromise review",
                "Coordinate analyst review of a suspected compromised identity.",
                [
                    "Validate sign-in telemetry and impacted sessions",
                    "Contact the identity owner through the approved channel",
                    "Request approval before revoking sessions or credentials",
                    "Record the identity provider confirmation and user follow-up",
                ],
            ),
            (
                "vulnerability_remediation",
                "Vulnerability remediation",
                "Track verification and remediation of an exposed vulnerability.",
                [
                    "Confirm affected asset and exploitable package",
                    "Assign a remediation owner and maintenance window",
                    "Document mitigation or patch evidence",
                    "Run a follow-up scan and record the result",
                ],
            ),
        ]:
            if db.scalar(select(ResponsePlaybook.id).where(ResponsePlaybook.key == key)) is None:
                db.add(ResponsePlaybook(key=key, name=name, description=description, steps=steps))
        controls = [
            ("ISO 27001", "A.5.15", "Access control"),
            ("ISO 27001", "A.5.24", "Incident management planning"),
            ("ISO 27001", "A.8.15", "Logging"),
            ("SOC 2", "CC6.1", "Logical access security"),
            ("SOC 2", "CC7.2", "System monitoring"),
            ("SOC 2", "CC7.4", "Incident response"),
            ("NIST CSF", "DE.CM-01", "Network and service monitoring"),
            ("NIST CSF", "RS.MA-01", "Incident management"),
            ("NIST CSF", "PR.AA-05", "Identity and access review"),
            ("CIS v8", "8.2", "Collect audit logs"),
            ("CIS v8", "17.4", "Establish incident response process"),
            ("CIS v8", "7.1", "Vulnerability management process"),
        ]
        for framework, control_key, title in controls:
            exists = db.scalar(
                select(ComplianceControl.id).where(
                    ComplianceControl.framework == framework,
                    ComplianceControl.control_key == control_key,
                )
            )
            if exists is None:
                db.add(
                    ComplianceControl(
                        framework=framework,
                        control_key=control_key,
                        title=title,
                        description="Track owner, assessment state and linked evidence.",
                    )
                )
        db.commit()
    yield


app = FastAPI(
    title="CipherOps AI API",
    version="0.1.0",
    description="CipherOps AI security operations, investigation and governance API",
    lifespan=lifespan,
)
app.add_middleware(
    CORSMiddleware,
    allow_origins=[x.strip() for x in settings.cors_origins.split(",")],
    allow_credentials=True,
    allow_methods=["GET", "POST", "PATCH"],
    allow_headers=["Authorization", "Content-Type"],
)
app.add_middleware(OperationalHeadersMiddleware)


@app.get("/health")
def health():
    return {"status": "ok", "service": "cipherops-api"}


@app.get("/ready", tags=["operations"])
def readiness():
    try:
        with SessionLocal() as db:
            db.execute(text("SELECT 1"))
    except Exception:
        return JSONResponse(
            status_code=503, content={"status": "not_ready", "checks": {"database": "failed"}}
        )
    return {"status": "ready", "checks": {"database": "ok"}}


app.include_router(auth.router)
app.include_router(incidents.router)
app.include_router(admin.router)
app.include_router(platform.router)
app.include_router(domains.router)
app.include_router(workflows.router)
app.include_router(governance.router)
app.include_router(search.router)
