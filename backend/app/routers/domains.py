"""Persisted security domain findings."""

from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import select
from sqlalchemy.orm import Session

from ..database import get_db
from ..dependencies import require_permission
from ..models import AuditLog, SecurityFinding, User
from ..schemas import SecurityFindingInput, SecurityFindingUpdate

router = APIRouter(prefix="/api/v1/findings", tags=["security-domains"])
DOMAINS = {"cloud", "identity", "vulnerability", "agent", "threat"}


@router.get("")
def list_findings(
    domain: str | None = Query(default=None),
    status: str | None = None,
    limit: int = Query(default=250, ge=1, le=1000),
    _: User = Depends(require_permission("findings:read")),
    db: Session = Depends(get_db),
):
    if domain and domain not in DOMAINS:
        raise HTTPException(status_code=422, detail="Unknown security domain")
    statement = select(SecurityFinding).order_by(
        SecurityFinding.risk_score.desc(), SecurityFinding.last_seen.desc()
    )
    if domain:
        statement = statement.where(SecurityFinding.domain == domain)
    if status:
        statement = statement.where(SecurityFinding.status == status)
    findings = db.scalars(statement.limit(limit)).all()
    return [
        {
            "id": row.id,
            "domain": row.domain,
            "external_id": row.external_id,
            "title": row.title,
            "description": row.description,
            "severity": row.severity,
            "status": row.status,
            "source": row.source,
            "asset_key": row.asset_key,
            "owner": row.owner,
            "risk_score": row.risk_score,
            "attributes": row.attributes,
            "first_seen": row.first_seen,
            "last_seen": row.last_seen,
        }
        for row in findings
    ]


@router.post("", status_code=201)
def create_finding(
    payload: SecurityFindingInput,
    actor: User = Depends(require_permission("findings:manage")),
    db: Session = Depends(get_db),
):
    """Allow analysts to record a finding/IOC; feeds use the ingestion-key endpoint."""
    source = "Analyst"
    existing = db.scalar(
        select(SecurityFinding).where(
            SecurityFinding.domain == payload.domain,
            SecurityFinding.source == source,
            SecurityFinding.external_id == payload.external_id,
        )
    )
    if existing:
        raise HTTPException(status_code=409, detail="This analyst finding already exists")
    row = SecurityFinding(source=source, **payload.model_dump())
    db.add(row)
    db.add(AuditLog(actor_id=actor.id, action="finding.created", resource=payload.external_id))
    db.commit()
    db.refresh(row)
    return {
        "id": row.id,
        "domain": row.domain,
        "external_id": row.external_id,
        "title": row.title,
        "severity": row.severity,
        "risk_score": row.risk_score,
        "attributes": row.attributes,
        "status": row.status,
        "source": row.source,
    }


@router.patch("/{finding_id}")
def update_finding(
    finding_id: int,
    payload: SecurityFindingUpdate,
    actor: User = Depends(require_permission("findings:manage")),
    db: Session = Depends(get_db),
):
    finding = db.get(SecurityFinding, finding_id)
    if not finding:
        raise HTTPException(status_code=404, detail="Finding not found")
    changes = payload.model_dump(exclude_unset=True)
    if not changes or any(value is None for value in changes.values()):
        raise HTTPException(status_code=422, detail="Provide a non-null status or owner")
    for field, value in changes.items():
        setattr(finding, field, value)
    finding.last_seen = datetime.now(timezone.utc)
    db.add(AuditLog(actor_id=actor.id, action="finding.updated", resource=finding.external_id))
    db.commit()
    db.refresh(finding)
    return {
        "id": finding.id,
        "domain": finding.domain,
        "external_id": finding.external_id,
        "status": finding.status,
        "owner": finding.owner,
        "updated": True,
    }
