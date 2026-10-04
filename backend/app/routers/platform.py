"""Persistent alert, asset, and telemetry integration APIs."""

import hashlib
import secrets
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, Header, HTTPException, Query
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from ..database import get_db
from ..dependencies import require_permission
from ..models import (
    Alert,
    Asset,
    AuditLog,
    Incident,
    IncidentEvent,
    Integration,
    SecurityFinding,
    TelemetryEvent,
    User,
)
from ..schemas import (
    AlertUpdate,
    AlertView,
    AssetView,
    IncidentView,
    IntegrationCreate,
    IntegrationStatusUpdate,
    TelemetryBatch,
    TelemetryIngestResult,
)

router = APIRouter(prefix="/api/v1", tags=["alerts-assets-telemetry"])


def _alert_key() -> str:
    return f"ALR-{secrets.token_hex(6).upper()}"


def _incident_key(db: Session) -> str:
    keys = db.scalars(select(Incident.incident_key)).all()
    sequence = [int(key[4:]) for key in keys if key.startswith("INC-") and key[4:].isdigit()]
    return f"INC-{max(sequence, default=1024) + 1:04d}"


@router.get("/alerts", response_model=list[AlertView])
def list_alerts(
    status: str | None = None,
    severity: str | None = None,
    limit: int = Query(default=100, ge=1, le=500),
    _: User = Depends(require_permission("alerts:read")),
    db: Session = Depends(get_db),
):
    query = select(Alert).order_by(Alert.last_seen.desc(), Alert.id.desc())
    if status:
        query = query.where(Alert.status == status)
    if severity:
        query = query.where(Alert.severity == severity)
    return list(db.scalars(query.limit(limit)))


@router.get("/alerts/{alert_key}", response_model=AlertView)
def get_alert(
    alert_key: str,
    _: User = Depends(require_permission("alerts:read")),
    db: Session = Depends(get_db),
):
    alert = db.scalar(select(Alert).where(Alert.alert_key == alert_key))
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")
    return alert


@router.patch("/alerts/{alert_key}", response_model=AlertView)
def update_alert(
    alert_key: str,
    payload: AlertUpdate,
    actor: User = Depends(require_permission("alerts:manage")),
    db: Session = Depends(get_db),
):
    alert = db.scalar(select(Alert).where(Alert.alert_key == alert_key))
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")
    changes = payload.model_dump(exclude_unset=True)
    if any(value is None for value in changes.values()):
        raise HTTPException(status_code=422, detail="Alert update values cannot be null")
    if not changes:
        raise HTTPException(status_code=422, detail="Provide a status or assignee to update")
    for field, value in changes.items():
        setattr(alert, field, value)
    db.add(AuditLog(actor_id=actor.id, action="alert.updated", resource=alert.alert_key))
    db.commit()
    db.refresh(alert)
    return alert


@router.post("/alerts/{alert_key}/promote", response_model=IncidentView, status_code=201)
def promote_alert(
    alert_key: str,
    actor: User = Depends(require_permission("incidents:manage")),
    db: Session = Depends(get_db),
):
    alert = db.scalar(select(Alert).where(Alert.alert_key == alert_key))
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")
    if alert.incident_id:
        incident = db.get(Incident, alert.incident_id)
        if incident:
            return incident
    incident = Incident(
        incident_key=_incident_key(db),
        title=alert.title,
        severity=alert.severity,
        risk_score={"Critical": 95, "High": 80, "Medium": 55, "Low": 25}.get(alert.severity, 0),
        status="Investigating",
        source=alert.source,
        asset_count=1,
        owner=actor.email,
    )
    db.add(incident)
    db.flush()
    alert.incident_id = incident.id
    alert.status = "Investigating"
    db.add(
        IncidentEvent(
            incident_id=incident.id,
            actor_id=actor.id,
            event_type="action",
            title="Alert promoted to incident",
            detail=f"Created from {alert.alert_key}",
        )
    )
    db.add(AuditLog(actor_id=actor.id, action="alert.promoted", resource=alert.alert_key))
    db.commit()
    db.refresh(incident)
    return incident


@router.get("/assets", response_model=list[AssetView])
def list_assets(
    query: str | None = None,
    provider: str | None = None,
    environment: str | None = None,
    limit: int = Query(default=200, ge=1, le=1000),
    _: User = Depends(require_permission("assets:read")),
    db: Session = Depends(get_db),
):
    statement = select(Asset).order_by(Asset.risk_score.desc(), Asset.last_seen.desc())
    if query:
        pattern = f"%{query.strip()}%"
        statement = statement.where(Asset.name.ilike(pattern) | Asset.asset_key.ilike(pattern))
    if provider:
        statement = statement.where(Asset.provider == provider)
    if environment:
        statement = statement.where(Asset.environment == environment)
    return list(db.scalars(statement.limit(limit)))


@router.get("/assets/{asset_key}", response_model=AssetView)
def get_asset(
    asset_key: str,
    _: User = Depends(require_permission("assets:read")),
    db: Session = Depends(get_db),
):
    asset = db.get(Asset, asset_key)
    if not asset:
        raise HTTPException(status_code=404, detail="Asset not found")
    return asset


@router.get("/integrations")
def list_integrations(
    _: User = Depends(require_permission("admin:manage")), db: Session = Depends(get_db)
):
    integrations = db.scalars(select(Integration).order_by(Integration.name)).all()
    return [
        {
            "id": item.id,
            "name": item.name,
            "provider": item.provider,
            "token_prefix": item.token_prefix,
            "is_active": item.is_active,
            "created_at": item.created_at,
            "last_ingested_at": item.last_ingested_at,
        }
        for item in integrations
    ]


@router.post("/integrations", status_code=201)
def create_integration(
    payload: IntegrationCreate,
    actor: User = Depends(require_permission("admin:manage")),
    db: Session = Depends(get_db),
):
    if db.scalar(select(Integration.id).where(Integration.name == payload.name)):
        raise HTTPException(status_code=409, detail="An integration with this name already exists")
    token = secrets.token_urlsafe(36)
    item = Integration(
        name=payload.name.strip(),
        provider=payload.provider.strip(),
        token_hash=hashlib.sha256(token.encode()).hexdigest(),
        token_prefix=token[:10],
    )
    db.add(item)
    db.flush()
    db.add(AuditLog(actor_id=actor.id, action="integration.created", resource=item.name))
    db.commit()
    return {"id": item.id, "name": item.name, "provider": item.provider, "token": token}


@router.patch("/integrations/{integration_id}")
def update_integration(
    integration_id: int,
    payload: IntegrationStatusUpdate,
    actor: User = Depends(require_permission("admin:manage")),
    db: Session = Depends(get_db),
):
    item = db.get(Integration, integration_id)
    if not item:
        raise HTTPException(status_code=404, detail="Integration not found")
    item.is_active = payload.is_active
    db.add(AuditLog(actor_id=actor.id, action="integration.status_changed", resource=item.name))
    db.commit()
    return {"id": item.id, "name": item.name, "is_active": item.is_active}


@router.post("/telemetry/ingest", response_model=TelemetryIngestResult)
def ingest_telemetry(
    batch: TelemetryBatch,
    x_ingestion_key: str | None = Header(default=None),
    db: Session = Depends(get_db),
):
    if not x_ingestion_key:
        raise HTTPException(status_code=401, detail="Integration key required")
    token_hash = hashlib.sha256(x_ingestion_key.encode()).hexdigest()
    integration = db.scalar(select(Integration).where(Integration.token_hash == token_hash))
    if not integration or not integration.is_active:
        raise HTTPException(status_code=401, detail="Integration key is invalid or inactive")
    accepted = duplicates = alerts_created = assets_upserted = 0
    source = integration.name
    severity_rank = {"Informational": 0, "Low": 1, "Medium": 2, "High": 3, "Critical": 4}
    for item in batch.events:
        event = db.scalar(
            select(TelemetryEvent).where(
                TelemetryEvent.source == source, TelemetryEvent.external_id == item.external_id
            )
        )
        asset_key = item.asset.asset_key if item.asset else None
        if event:
            duplicates += 1
            event.event_type = item.event_type
            event.severity = item.severity
            event.summary = item.summary
            event.asset_key = asset_key
            event.occurred_at = item.occurred_at
            event.payload = item.attributes
        else:
            event = TelemetryEvent(
                source=source,
                external_id=item.external_id,
                event_type=item.event_type,
                severity=item.severity,
                summary=item.summary,
                asset_key=asset_key,
                occurred_at=item.occurred_at,
                payload=item.attributes,
            )
            db.add(event)
            accepted += 1
        if item.asset:
            asset = db.get(Asset, item.asset.asset_key)
            values = item.asset.model_dump(exclude={"asset_key"})
            if asset:
                for field, value in values.items():
                    setattr(asset, field, value)
            else:
                asset = Asset(asset_key=item.asset.asset_key, **values)
                db.add(asset)
            asset.last_seen = datetime.now(timezone.utc)
            assets_upserted += 1
        for finding_input in item.findings:
            finding = db.scalar(
                select(SecurityFinding).where(
                    SecurityFinding.domain == finding_input.domain,
                    SecurityFinding.source == source,
                    SecurityFinding.external_id == finding_input.external_id,
                )
            )
            values = finding_input.model_dump(exclude={"domain", "external_id"})
            if finding:
                for field, value in values.items():
                    setattr(finding, field, value)
                finding.last_seen = datetime.now(timezone.utc)
            else:
                db.add(
                    SecurityFinding(
                        domain=finding_input.domain,
                        source=source,
                        external_id=finding_input.external_id,
                        **values,
                    )
                )
        observed = item.attributes.get("observed_indicators", item.attributes.get("indicators", []))
        if isinstance(observed, (str, dict)):
            observed = [observed]
        if not isinstance(observed, list):
            observed = []
        if len(observed) > 100:
            raise HTTPException(
                status_code=422,
                detail="At most 100 observed indicators are allowed per event",
            )
        observed_values = {
            str(value.get("value", "") if isinstance(value, dict) else value).casefold()
            for value in observed
        }
        matches = (
            db.scalars(
                select(SecurityFinding).where(
                    SecurityFinding.domain == "threat",
                    func.lower(SecurityFinding.external_id).in_(observed_values),
                    SecurityFinding.status.not_in(["Resolved", "Accepted risk"]),
                )
            ).all()
            if observed_values
            else []
        )
        effective_severity = item.severity
        if matches:
            effective_severity = max(
                [item.severity, *(row.severity for row in matches)],
                key=lambda value: severity_rank[value],
            )
            payload = dict(item.attributes)
            payload["threat_intel_matches"] = [
                {
                    "indicator": row.attributes.get("value") or row.attributes.get("indicator"),
                    "type": row.attributes.get("indicator_type", "unknown"),
                    "severity": row.severity,
                    "finding_id": row.id,
                }
                for row in matches
            ]
            event.payload = payload
        alert_summary = item.summary
        if matches:
            match_names = ", ".join(
                str(row.attributes.get("value") or row.attributes.get("indicator"))
                for row in matches[:5]
            )
            alert_summary = f"{item.summary} · Threat intel match: {match_names}"
        if effective_severity != "Informational":
            fingerprint = hashlib.sha256(f"{source}|{item.external_id}".encode()).hexdigest()
            alert = db.scalar(select(Alert).where(Alert.fingerprint == fingerprint))
            if alert:
                alert.last_seen = datetime.now(timezone.utc)
                alert.description = alert_summary
                if severity_rank[effective_severity] > severity_rank[alert.severity]:
                    alert.severity = effective_severity
                alert.status = "New" if alert.status in {"Resolved", "Suppressed"} else alert.status
            else:
                db.add(
                    Alert(
                        alert_key=_alert_key(),
                        fingerprint=fingerprint,
                        title=alert_summary[:240],
                        description=alert_summary,
                        severity=effective_severity,
                        source=source,
                        external_id=item.external_id,
                        asset_key=asset_key,
                        first_seen=item.occurred_at,
                        last_seen=datetime.now(timezone.utc),
                    )
                )
                alerts_created += 1
        # Sessions disable autoflush globally; flush each normalized event so
        # repeated source IDs later in the same batch deduplicate correctly.
        db.flush()
    integration.last_ingested_at = datetime.now(timezone.utc)
    db.commit()
    return TelemetryIngestResult(
        accepted=accepted,
        duplicates=duplicates,
        alerts_created=alerts_created,
        assets_upserted=assets_upserted,
    )


@router.get("/telemetry/events")
def list_telemetry_events(
    since: datetime | None = None,
    limit: int = Query(default=100, ge=1, le=500),
    _: User = Depends(require_permission("alerts:read")),
    db: Session = Depends(get_db),
):
    statement = select(TelemetryEvent).order_by(TelemetryEvent.received_at.desc())
    if since:
        statement = statement.where(TelemetryEvent.received_at > since)
    events = db.scalars(statement.limit(limit)).all()
    return [
        {
            "id": event.id,
            "source": event.source,
            "external_id": event.external_id,
            "event_type": event.event_type,
            "severity": event.severity,
            "summary": event.summary,
            "asset_key": event.asset_key,
            "occurred_at": event.occurred_at,
            "received_at": event.received_at,
            "payload": event.payload,
        }
        for event in events
    ]
