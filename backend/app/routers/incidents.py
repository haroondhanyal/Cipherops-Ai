import re
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from ..database import get_db
from ..dependencies import require_permission
from ..models import (
    Alert,
    AuditLog,
    Incident,
    IncidentEvent,
    User,
)
from ..schemas import (
    IncidentCreate,
    IncidentEventCreate,
    IncidentUpdate,
    IncidentView,
)

router = APIRouter(prefix="/api/v1", tags=["operations"])


@router.get("/dashboard/summary", dependencies=[Depends(require_permission("dashboard:read"))])
def dashboard_summary(db: Session = Depends(get_db)):

    total = db.scalar(select(func.count()).select_from(Incident)) or 0
    open_incidents = (
        db.scalar(select(func.count()).select_from(Incident).where(Incident.status != "Closed"))
        or 0
    )
    critical = (
        db.scalar(
            select(func.count())
            .select_from(Incident)
            .where(Incident.severity == "Critical", Incident.status != "Closed")
        )
        or 0
    )
    high = (
        db.scalar(
            select(func.count())
            .select_from(Incident)
            .where(Incident.severity == "High", Incident.status != "Closed")
        )
        or 0
    )
    investigating = (
        db.scalar(
            select(func.count()).select_from(Incident).where(Incident.status == "Investigating")
        )
        or 0
    )
    risk = (
        db.scalar(
            select(func.count())
            .select_from(Incident)
            .where(Incident.risk_score >= 70, Incident.status != "Closed")
        )
        or 0
    )
    active_alerts = (
        db.scalar(
            select(func.count())
            .select_from(Alert)
            .where(Alert.status.not_in(["Resolved", "Suppressed"]))
        )
        or 0
    )
    return {
        "critical_incidents": critical,
        "high_severity_incidents": high,
        "open_investigations": investigating,
        "incidents_at_risk": risk,
        "security_score": max(0, 100 - min(100, risk * 2)),
        "total_incidents": total,
        "open_incidents": open_incidents,
        "active_alerts": active_alerts,
    }


@router.get("/incidents", response_model=list[IncidentView])
def list_incidents(
    _: User = Depends(require_permission("incidents:read")), db: Session = Depends(get_db)
):
    return list(
        db.scalars(
            select(Incident).order_by(Incident.created_at.desc(), Incident.id.desc()).limit(100)
        )
    )


@router.post("/incidents", response_model=IncidentView, status_code=201)
def create_incident(
    payload: IncidentCreate,
    actor: User = Depends(require_permission("incidents:manage")),
    db: Session = Depends(get_db),
):
    sequence = [
        int(key.split("-")[1])
        for key in db.scalars(select(Incident.incident_key)).all()
        if key.startswith("INC-") and key.split("-")[1].isdigit()
    ]
    incident = Incident(
        incident_key=f"INC-{max(sequence, default=1024) + 1:04d}",
        title=payload.title.strip(),
        severity=payload.severity,
        risk_score=payload.risk_score,
        status="New",
        source=payload.source,
        asset_count=payload.asset_count,
        owner=actor.email,
    )
    db.add(incident)
    db.flush()
    db.add(
        IncidentEvent(
            incident_id=incident.id,
            actor_id=actor.id,
            event_type="action",
            title="Incident created",
            detail=f"{incident.severity} severity · risk score {incident.risk_score}",
        )
    )
    db.add(AuditLog(actor_id=actor.id, action="incident.created", resource=incident.incident_key))
    db.commit()
    db.refresh(incident)
    return incident


@router.get("/incidents/{incident_key}", response_model=IncidentView)
def get_incident(
    incident_key: str,
    _: User = Depends(require_permission("incidents:read")),
    db: Session = Depends(get_db),
):
    incident = db.scalar(select(Incident).where(Incident.incident_key == incident_key))
    if not incident:
        raise HTTPException(status_code=404, detail="Incident not found")
    return incident


@router.patch("/incidents/{incident_key}", response_model=IncidentView)
def update_incident(
    incident_key: str,
    payload: IncidentUpdate,
    actor: User = Depends(require_permission("incidents:manage")),
    db: Session = Depends(get_db),
):
    incident = db.scalar(select(Incident).where(Incident.incident_key == incident_key))
    if not incident:
        raise HTTPException(status_code=404, detail="Incident not found")
    changes = payload.model_dump(exclude_unset=True)
    if any(value is None for value in changes.values()):
        raise HTTPException(status_code=422, detail="Incident update values cannot be null")
    if not changes:
        raise HTTPException(status_code=422, detail="Provide an incident field to update")
    for field, value in changes.items():
        setattr(incident, field, value)
    incident.updated_at = datetime.now(timezone.utc)
    db.add(
        IncidentEvent(
            incident_id=incident.id,
            actor_id=actor.id,
            event_type="action",
            title="Incident updated",
            detail=", ".join(f"{key}: {value}" for key, value in changes.items()),
        )
    )
    db.add(AuditLog(actor_id=actor.id, action="incident.updated", resource=incident_key))
    db.commit()
    db.refresh(incident)
    return incident


@router.get("/incidents/{incident_key}/events")
def list_incident_events(
    incident_key: str,
    _: User = Depends(require_permission("incidents:read")),
    db: Session = Depends(get_db),
):
    incident = db.scalar(select(Incident).where(Incident.incident_key == incident_key))
    if not incident:
        raise HTTPException(status_code=404, detail="Incident not found")
    events = db.scalars(
        select(IncidentEvent)
        .where(IncidentEvent.incident_id == incident.id)
        .order_by(IncidentEvent.created_at.asc(), IncidentEvent.id.asc())
    ).all()
    users = {
        user.id: user.email
        for user in db.scalars(
            select(User).where(User.id.in_([e.actor_id for e in events if e.actor_id]))
        ).all()
    }
    return [
        {
            "id": event.id,
            "event_type": event.event_type,
            "title": event.title,
            "detail": event.detail,
            "mentions": event.mentions or [],
            "actor": users.get(event.actor_id, "System"),
            "created_at": event.created_at,
        }
        for event in events
    ]


@router.post("/incidents/{incident_key}/events", status_code=201)
def create_incident_event(
    incident_key: str,
    payload: IncidentEventCreate,
    actor: User = Depends(require_permission("incidents:manage")),
    db: Session = Depends(get_db),
):
    incident = db.scalar(select(Incident).where(Incident.incident_key == incident_key))
    if not incident:
        raise HTTPException(status_code=404, detail="Incident not found")
    mentioned_emails = {
        email.casefold()
        for email in re.findall(r"(?<![\w.+-])@([\w.+-]+@[\w.-]+\.[A-Za-z]{2,})", payload.detail)
    }
    valid_mentions = (
        db.scalars(
            select(User.email).where(
                User.is_active.is_(True), func.lower(User.email).in_(mentioned_emails)
            )
        ).all()
        if mentioned_emails
        else []
    )
    event = IncidentEvent(
        incident_id=incident.id,
        actor_id=actor.id,
        event_type=payload.event_type,
        title=payload.title.strip(),
        detail=payload.detail.strip(),
        mentions=sorted(valid_mentions),
    )
    db.add(event)
    db.add(
        AuditLog(actor_id=actor.id, action=f"incident.{payload.event_type}", resource=incident_key)
    )
    db.commit()
    db.refresh(event)
    return {
        "id": event.id,
        "event_type": event.event_type,
        "title": event.title,
        "detail": event.detail,
        "mentions": event.mentions,
        "actor": actor.email,
        "created_at": event.created_at,
    }
