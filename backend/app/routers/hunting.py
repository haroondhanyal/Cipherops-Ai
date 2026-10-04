"""Threat hunting queries and lightweight, auditable telemetry detection rules."""

from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import String, cast, or_, select
from sqlalchemy.orm import Session

from ..database import get_db
from ..dependencies import require_permission
from ..models import AuditLog, DetectionRule, SavedHuntQuery, TelemetryEvent, User
from ..schemas import DetectionRuleCreate, DetectionRuleUpdate, SavedHuntQueryCreate

router = APIRouter(prefix="/api/v1", tags=["threat-hunting-and-detection"])


def rule_view(rule: DetectionRule) -> dict:
    return {
        "id": rule.id,
        "name": rule.name,
        "description": rule.description,
        "event_type": rule.event_type,
        "minimum_severity": rule.minimum_severity,
        "summary_contains": rule.summary_contains,
        "enabled": rule.enabled,
        "created_at": rule.created_at,
        "updated_at": rule.updated_at,
    }


@router.get("/hunting/search")
def hunt(
    q: str = Query(min_length=2, max_length=240),
    limit: int = Query(default=100, ge=1, le=500),
    _: User = Depends(require_permission("alerts:read")),
    db: Session = Depends(get_db),
):
    term = q.strip()
    pattern = f"%{term.replace('%', r'\%').replace('_', r'\_')}%"
    events = db.scalars(
        select(TelemetryEvent)
        .where(
            or_(
                TelemetryEvent.external_id.ilike(pattern, escape="\\"),
                TelemetryEvent.event_type.ilike(pattern, escape="\\"),
                TelemetryEvent.summary.ilike(pattern, escape="\\"),
                TelemetryEvent.asset_key.ilike(pattern, escape="\\"),
                cast(TelemetryEvent.payload, String).ilike(pattern, escape="\\"),
            )
        )
        .order_by(TelemetryEvent.occurred_at.desc())
        .limit(limit)
    ).all()
    return [
        {
            "id": row.id,
            "kind": "telemetry",
            "key": row.external_id,
            "source": row.source,
            "event_type": row.event_type,
            "severity": row.severity,
            "summary": row.summary,
            "asset_key": row.asset_key,
            "occurred_at": row.occurred_at,
            "payload": row.payload,
            "ioc_matches": row.payload.get("threat_intel_matches", []),
            "rule_matches": row.payload.get("detection_rule_matches", []),
        }
        for row in events
    ]


@router.get("/hunting/saved-queries")
def list_hunt_queries(
    user: User = Depends(require_permission("alerts:read")), db: Session = Depends(get_db)
):
    rows = db.scalars(
        select(SavedHuntQuery)
        .where(SavedHuntQuery.user_id == user.id)
        .order_by(SavedHuntQuery.created_at.desc())
    ).all()
    return [
        {"id": r.id, "name": r.name, "query": r.query, "created_at": r.created_at} for r in rows
    ]


@router.post("/hunting/saved-queries", status_code=201)
def save_hunt_query(
    payload: SavedHuntQueryCreate,
    user: User = Depends(require_permission("alerts:manage")),
    db: Session = Depends(get_db),
):
    row = SavedHuntQuery(user_id=user.id, name=payload.name.strip(), query=payload.query.strip())
    db.add(row)
    db.commit()
    db.refresh(row)
    return {"id": row.id, "name": row.name, "query": row.query, "created_at": row.created_at}


@router.delete("/hunting/saved-queries/{query_id}", status_code=204)
def delete_hunt_query(
    query_id: int,
    user: User = Depends(require_permission("alerts:manage")),
    db: Session = Depends(get_db),
):
    row = db.scalar(
        select(SavedHuntQuery).where(
            SavedHuntQuery.id == query_id, SavedHuntQuery.user_id == user.id
        )
    )
    if row is None:
        raise HTTPException(status_code=404, detail="Saved query not found")
    db.delete(row)
    db.commit()


@router.get("/detection-rules")
def list_detection_rules(
    _: User = Depends(require_permission("detection:read")), db: Session = Depends(get_db)
):
    return [
        rule_view(row) for row in db.scalars(select(DetectionRule).order_by(DetectionRule.name))
    ]


@router.post("/detection-rules", status_code=201)
def create_detection_rule(
    payload: DetectionRuleCreate,
    actor: User = Depends(require_permission("detection:manage")),
    db: Session = Depends(get_db),
):
    name = payload.name.strip()
    if db.scalar(select(DetectionRule.id).where(DetectionRule.name == name)):
        raise HTTPException(status_code=409, detail="A rule with this name already exists")
    rule = DetectionRule(
        **payload.model_dump(exclude={"name"}),
        name=name,
        event_type=payload.event_type.strip() if payload.event_type else None,
        summary_contains=payload.summary_contains.strip() if payload.summary_contains else None,
        created_by=actor.id,
    )
    db.add(rule)
    db.flush()
    db.add(AuditLog(actor_id=actor.id, action="detection_rule.created", resource=rule.name))
    db.commit()
    db.refresh(rule)
    return rule_view(rule)


@router.patch("/detection-rules/{rule_id}")
def update_detection_rule(
    rule_id: int,
    payload: DetectionRuleUpdate,
    actor: User = Depends(require_permission("detection:manage")),
    db: Session = Depends(get_db),
):
    rule = db.get(DetectionRule, rule_id)
    if rule is None:
        raise HTTPException(status_code=404, detail="Detection rule not found")
    changes = payload.model_dump(exclude_unset=True)
    for key, value in changes.items():
        setattr(rule, key, value.strip() if isinstance(value, str) else value)
    rule.updated_at = datetime.now(timezone.utc)
    db.add(AuditLog(actor_id=actor.id, action="detection_rule.updated", resource=rule.name))
    db.commit()
    db.refresh(rule)
    return rule_view(rule)


@router.post("/detection-rules/{rule_id}/simulate")
def simulate_detection_rule(
    rule_id: int,
    _: User = Depends(require_permission("detection:read")),
    db: Session = Depends(get_db),
):
    rule = db.get(DetectionRule, rule_id)
    if rule is None:
        raise HTTPException(status_code=404, detail="Detection rule not found")
    ranks = {"Informational": 0, "Low": 1, "Medium": 2, "High": 3, "Critical": 4}
    statement = select(TelemetryEvent)
    if rule.event_type:
        statement = statement.where(TelemetryEvent.event_type.ilike(rule.event_type))
    if rule.summary_contains:
        statement = statement.where(TelemetryEvent.summary.ilike(f"%{rule.summary_contains}%"))
    statement = statement.where(
        TelemetryEvent.severity.in_(
            [name for name, rank in ranks.items() if rank >= ranks[rule.minimum_severity]]
        )
    )
    rows = db.scalars(statement.order_by(TelemetryEvent.occurred_at.desc()).limit(100)).all()
    return {
        "rule": rule.name,
        "matched": len(rows),
        "sample": [
            {
                "source": row.source,
                "key": row.external_id,
                "severity": row.severity,
                "summary": row.summary,
            }
            for row in rows[:20]
        ],
        "simulated_at": datetime.now(timezone.utc),
    }
