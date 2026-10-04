"""YARA rule authoring and bounded telemetry simulation."""

import json
import time
from datetime import datetime, timezone

import yara
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import select
from sqlalchemy.orm import Session

from ..database import get_db
from ..dependencies import require_permission
from ..models import AuditLog, TelemetryEvent, User, YaraRule
from ..schemas import YaraRuleCreate, YaraRuleUpdate

router = APIRouter(prefix="/api/v1", tags=["yara-rules"])


def compile_rule(source: str, namespace: str):
    try:
        return yara.compile(sources={namespace: source}, error_on_warning=True)
    except yara.SyntaxError as exc:
        raise HTTPException(status_code=422, detail=f"Invalid YARA rule: {exc}") from exc
    except yara.Error as exc:
        raise HTTPException(
            status_code=422, detail=f"YARA compiler rejected this rule: {exc}"
        ) from exc


def rule_view(rule: YaraRule) -> dict:
    return {
        "id": rule.id,
        "name": rule.name,
        "namespace": rule.namespace,
        "description": rule.description,
        "source": rule.source,
        "severity": rule.severity,
        "enabled": rule.enabled,
        "created_at": rule.created_at,
        "updated_at": rule.updated_at,
    }


@router.get("/yara-rules")
def list_yara_rules(
    _: User = Depends(require_permission("detection:read")), db: Session = Depends(get_db)
):
    return [rule_view(row) for row in db.scalars(select(YaraRule).order_by(YaraRule.name))]


@router.post("/yara-rules", status_code=201)
def create_yara_rule(
    payload: YaraRuleCreate,
    actor: User = Depends(require_permission("detection:manage")),
    db: Session = Depends(get_db),
):
    name = payload.name.strip()
    if db.scalar(select(YaraRule.id).where(YaraRule.name == name)):
        raise HTTPException(status_code=409, detail="A YARA rule with this name already exists")
    compile_rule(payload.source, payload.namespace)
    rule = YaraRule(
        name=name,
        namespace=payload.namespace,
        description=payload.description.strip(),
        source=payload.source,
        severity=payload.severity,
        enabled=payload.enabled,
        created_by=actor.id,
    )
    db.add(rule)
    db.flush()
    db.add(AuditLog(actor_id=actor.id, action="yara_rule.created", resource=rule.name))
    db.commit()
    db.refresh(rule)
    return rule_view(rule)


@router.patch("/yara-rules/{rule_id}")
def update_yara_rule(
    rule_id: int,
    payload: YaraRuleUpdate,
    actor: User = Depends(require_permission("detection:manage")),
    db: Session = Depends(get_db),
):
    rule = db.get(YaraRule, rule_id)
    if rule is None:
        raise HTTPException(status_code=404, detail="YARA rule not found")
    changes = payload.model_dump(exclude_unset=True)
    if any(value is None for value in changes.values()):
        raise HTTPException(status_code=422, detail="YARA rule fields cannot be set to null")
    if "name" in changes:
        changes["name"] = changes["name"].strip()
        duplicate = db.scalar(
            select(YaraRule.id).where(YaraRule.name == changes["name"], YaraRule.id != rule.id)
        )
        if duplicate:
            raise HTTPException(status_code=409, detail="A YARA rule with this name already exists")
    namespace = changes.get("namespace", rule.namespace)
    source = changes.get("source", rule.source)
    if "namespace" in changes or "source" in changes:
        compile_rule(source, namespace)
    for key, value in changes.items():
        setattr(
            rule, key, value.strip() if key == "description" and isinstance(value, str) else value
        )
    rule.updated_at = datetime.now(timezone.utc)
    db.add(AuditLog(actor_id=actor.id, action="yara_rule.updated", resource=rule.name))
    db.commit()
    db.refresh(rule)
    return rule_view(rule)


@router.delete("/yara-rules/{rule_id}", status_code=204)
def delete_yara_rule(
    rule_id: int,
    actor: User = Depends(require_permission("detection:manage")),
    db: Session = Depends(get_db),
):
    rule = db.get(YaraRule, rule_id)
    if rule is None:
        raise HTTPException(status_code=404, detail="YARA rule not found")
    db.add(AuditLog(actor_id=actor.id, action="yara_rule.deleted", resource=rule.name))
    db.delete(rule)
    db.commit()


@router.post("/yara-rules/{rule_id}/simulate")
def simulate_yara_rule(
    rule_id: int,
    _: User = Depends(require_permission("detection:read")),
    db: Session = Depends(get_db),
):
    rule = db.get(YaraRule, rule_id)
    if rule is None:
        raise HTTPException(status_code=404, detail="YARA rule not found")
    compiled = compile_rule(rule.source, rule.namespace)
    events = db.scalars(
        select(TelemetryEvent).order_by(TelemetryEvent.occurred_at.desc()).limit(500)
    ).all()
    sample = []
    matched = 0
    deadline = time.monotonic() + 10
    for event in events:
        data = json.dumps(
            {
                "source": event.source,
                "event_type": event.event_type,
                "severity": event.severity,
                "summary": event.summary,
                "asset_key": event.asset_key,
                "payload": event.payload or {},
            },
            ensure_ascii=False,
            sort_keys=True,
            default=str,
        ).encode("utf-8")
        if time.monotonic() > deadline:
            raise HTTPException(
                status_code=422, detail="Rule exceeded the 10 second total simulation limit"
            )
        try:
            matches = compiled.match(data=data, timeout=1)
        except yara.TimeoutError as exc:
            raise HTTPException(
                status_code=422, detail="Rule exceeded the 1 second per-event simulation limit"
            ) from exc
        if matches:
            matched += 1
            if len(sample) < 20:
                sample.append(
                    {
                        "source": event.source,
                        "key": event.external_id,
                        "event_type": event.event_type,
                        "severity": event.severity,
                        "summary": event.summary,
                        "matched_strings": [item.identifier for item in matches[0].strings],
                    }
                )
    return {
        "rule": rule.name,
        "examined": len(events),
        "matched": matched,
        "sample": sample,
        "simulated_at": datetime.now(timezone.utc),
    }
