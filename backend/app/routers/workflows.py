"""Investigation evidence, approval gates and response playbook records."""

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
    IncidentEvidence,
    PlaybookRun,
    ResponseAction,
    ResponsePlaybook,
    SecurityFinding,
    TelemetryEvent,
    User,
)
from ..schemas import (
    AutomationRunCreate,
    EvidenceCreate,
    PlaybookRunCreate,
    ResponseActionCreate,
    ResponseActionDecision,
)

router = APIRouter(prefix="/api/v1", tags=["investigation-workflows"])


def incident_or_404(db: Session, key: str) -> Incident:
    incident = db.scalar(select(Incident).where(Incident.incident_key == key))
    if not incident:
        raise HTTPException(status_code=404, detail="Incident not found")
    return incident


def action_view(action: ResponseAction, requesters: dict[int, str], deciders: dict[int, str]):
    return {
        "id": action.id,
        "action": action.action,
        "scope": action.scope,
        "status": action.status,
        "requested_by": requesters.get(action.requested_by, "Unknown"),
        "decided_by": deciders.get(action.decided_by, "") if action.decided_by else "",
        "decision_detail": action.decision_detail,
        "created_at": action.created_at,
        "decided_at": action.decided_at,
    }


@router.get("/incidents/{incident_key}/evidence")
def list_evidence(
    incident_key: str,
    _: User = Depends(require_permission("incidents:read")),
    db: Session = Depends(get_db),
):
    incident = incident_or_404(db, incident_key)
    rows = db.scalars(
        select(IncidentEvidence)
        .where(IncidentEvidence.incident_id == incident.id)
        .order_by(IncidentEvidence.created_at.desc())
    ).all()
    return [
        {
            "id": row.id,
            "evidence_type": row.evidence_type,
            "title": row.title,
            "source_uri": row.source_uri,
            "sha256": row.sha256,
            "notes": row.notes,
            "created_at": row.created_at,
        }
        for row in rows
    ]


@router.post("/incidents/{incident_key}/evidence", status_code=201)
def add_evidence(
    incident_key: str,
    payload: EvidenceCreate,
    actor: User = Depends(require_permission("incidents:manage")),
    db: Session = Depends(get_db),
):
    incident = incident_or_404(db, incident_key)
    evidence = IncidentEvidence(incident_id=incident.id, added_by=actor.id, **payload.model_dump())
    db.add(evidence)
    db.add(
        IncidentEvent(
            incident_id=incident.id,
            actor_id=actor.id,
            event_type="evidence",
            title=f"Evidence added: {payload.title.strip()}",
            detail=payload.source_uri or payload.notes[:500],
        )
    )
    db.add(AuditLog(actor_id=actor.id, action="incident.evidence_added", resource=incident_key))
    db.commit()
    db.refresh(evidence)
    return {
        "id": evidence.id,
        "evidence_type": evidence.evidence_type,
        "title": evidence.title,
        "source_uri": evidence.source_uri,
        "sha256": evidence.sha256,
        "notes": evidence.notes,
        "created_at": evidence.created_at,
    }


@router.get("/incidents/{incident_key}/response-actions")
def list_response_actions(
    incident_key: str,
    _: User = Depends(require_permission("incidents:read")),
    db: Session = Depends(get_db),
):
    incident = incident_or_404(db, incident_key)
    actions = db.scalars(
        select(ResponseAction)
        .where(ResponseAction.incident_id == incident.id)
        .order_by(ResponseAction.created_at.desc())
    ).all()
    user_ids = {item.requested_by for item in actions} | {
        item.decided_by for item in actions if item.decided_by
    }
    users = db.scalars(select(User).where(User.id.in_(user_ids))).all() if user_ids else []
    names = {user.id: user.email for user in users}
    return [action_view(item, names, names) for item in actions]


@router.post("/incidents/{incident_key}/response-actions", status_code=201)
def request_response_action(
    incident_key: str,
    payload: ResponseActionCreate,
    actor: User = Depends(require_permission("incidents:manage")),
    db: Session = Depends(get_db),
):
    incident = incident_or_404(db, incident_key)
    item = ResponseAction(
        incident_id=incident.id,
        requested_by=actor.id,
        action=payload.action.strip(),
        scope=payload.scope.strip(),
    )
    db.add(item)
    db.add(
        IncidentEvent(
            incident_id=incident.id,
            actor_id=actor.id,
            event_type="approval",
            title=f"Approval requested: {payload.action.strip()}",
            detail=payload.scope.strip(),
        )
    )
    db.add(
        AuditLog(
            actor_id=actor.id, action="incident.response_approval_requested", resource=incident_key
        )
    )
    db.commit()
    db.refresh(item)
    return action_view(item, {actor.id: actor.email}, {})


@router.post("/incidents/{incident_key}/response-actions/{action_id}/decision")
def decide_response_action(
    incident_key: str,
    action_id: int,
    payload: ResponseActionDecision,
    actor: User = Depends(require_permission("response:approve")),
    db: Session = Depends(get_db),
):
    incident = incident_or_404(db, incident_key)
    item = db.scalar(select(ResponseAction).where(ResponseAction.id == action_id).with_for_update())
    if not item or item.incident_id != incident.id:
        raise HTTPException(status_code=404, detail="Response action not found")
    if item.requested_by == actor.id:
        raise HTTPException(status_code=409, detail="A requester cannot approve their own action")
    if item.status != "Pending":
        raise HTTPException(status_code=409, detail="Response action has already been decided")
    item.status = payload.decision
    item.decided_by = actor.id
    item.decision_detail = payload.note.strip()
    item.decided_at = datetime.now(timezone.utc)
    db.add(
        IncidentEvent(
            incident_id=incident.id,
            actor_id=actor.id,
            event_type="approval",
            title=f"Response action {payload.decision.lower()}",
            detail=item.action,
        )
    )
    db.add(
        AuditLog(
            actor_id=actor.id,
            action=f"response_action.{payload.decision.lower()}",
            resource=f"{incident_key}:{action_id}",
        )
    )
    db.commit()
    db.refresh(item)
    return action_view(item, {item.requested_by: str(item.requested_by)}, {actor.id: actor.email})


@router.get("/response-playbooks")
def list_playbooks(
    _: User = Depends(require_permission("incidents:read")), db: Session = Depends(get_db)
):
    rows = db.scalars(
        select(ResponsePlaybook)
        .where(ResponsePlaybook.enabled.is_(True))
        .order_by(ResponsePlaybook.name)
    ).all()
    return [
        {
            "id": row.id,
            "key": row.key,
            "name": row.name,
            "description": row.description,
            "steps": row.steps,
        }
        for row in rows
    ]


@router.get("/incidents/{incident_key}/playbook-runs")
def list_playbook_runs(
    incident_key: str,
    _: User = Depends(require_permission("incidents:read")),
    db: Session = Depends(get_db),
):
    incident = incident_or_404(db, incident_key)
    rows = db.execute(
        select(PlaybookRun, ResponsePlaybook)
        .join(ResponsePlaybook)
        .where(PlaybookRun.incident_id == incident.id)
        .order_by(PlaybookRun.created_at.desc())
    ).all()
    return [
        {
            "id": run.id,
            "playbook": book.name,
            "requested_by": run.requested_by,
            "steps": book.steps,
            "status": run.status,
            "execution_mode": run.execution_mode,
            "approval_note": run.approval_note,
            "created_at": run.created_at,
        }
        for run, book in rows
    ]


@router.post("/incidents/{incident_key}/playbook-runs", status_code=201)
def request_playbook_run(
    incident_key: str,
    payload: PlaybookRunCreate,
    actor: User = Depends(require_permission("incidents:manage")),
    db: Session = Depends(get_db),
):
    incident = incident_or_404(db, incident_key)
    book = db.scalar(
        select(ResponsePlaybook).where(
            ResponsePlaybook.key == payload.playbook_key, ResponsePlaybook.enabled.is_(True)
        )
    )
    if not book:
        raise HTTPException(status_code=404, detail="Response playbook not found")
    run = PlaybookRun(playbook_id=book.id, incident_id=incident.id, requested_by=actor.id)
    db.add(run)
    db.add(
        IncidentEvent(
            incident_id=incident.id,
            actor_id=actor.id,
            event_type="approval",
            title=f"Playbook approval requested: {book.name}",
            detail="Manual checklist only. No external response action is executed.",
        )
    )
    db.add(AuditLog(actor_id=actor.id, action="playbook.run_requested", resource=incident_key))
    db.commit()
    db.refresh(run)
    return {
        "id": run.id,
        "playbook": book.name,
        "status": run.status,
        "execution_mode": run.execution_mode,
        "created_at": run.created_at,
    }


@router.post("/incidents/{incident_key}/playbook-runs/{run_id}/decision")
def decide_playbook_run(
    incident_key: str,
    run_id: int,
    payload: ResponseActionDecision,
    actor: User = Depends(require_permission("response:approve")),
    db: Session = Depends(get_db),
):
    incident = incident_or_404(db, incident_key)
    run = db.scalar(select(PlaybookRun).where(PlaybookRun.id == run_id).with_for_update())
    if not run or run.incident_id != incident.id:
        raise HTTPException(status_code=404, detail="Playbook run not found")
    if run.requested_by == actor.id:
        raise HTTPException(status_code=409, detail="A requester cannot approve their own playbook")
    if run.status != "Pending approval":
        raise HTTPException(status_code=409, detail="Playbook run has already been decided")
    run.status = payload.decision
    run.decided_by = actor.id
    run.approval_note = payload.note.strip()
    run.decided_at = datetime.now(timezone.utc)
    incident = db.get(Incident, run.incident_id)
    book = db.get(ResponsePlaybook, run.playbook_id)
    db.add(
        IncidentEvent(
            incident_id=incident.id,
            actor_id=actor.id,
            event_type="approval",
            title=f"Response playbook {payload.decision.lower()}: {book.name}",
            detail=run.approval_note,
        )
    )
    db.add(
        AuditLog(
            actor_id=actor.id,
            action=f"playbook.{payload.decision.lower()}",
            resource=f"{incident_key}:{run_id}",
        )
    )
    db.commit()
    return {"id": run.id, "status": run.status, "approval_note": run.approval_note}


@router.post("/incidents/{incident_key}/playbook-runs/{run_id}/complete")
def complete_manual_playbook(
    incident_key: str,
    run_id: int,
    actor: User = Depends(require_permission("incidents:manage")),
    db: Session = Depends(get_db),
):
    incident = incident_or_404(db, incident_key)
    run = db.scalar(select(PlaybookRun).where(PlaybookRun.id == run_id).with_for_update())
    if not run or run.incident_id != incident.id:
        raise HTTPException(status_code=404, detail="Playbook run not found")
    if run.status != "Approved":
        raise HTTPException(
            status_code=409, detail="Only an approved playbook can be marked complete"
        )
    run.status = "Completed"
    db.add(
        IncidentEvent(
            incident_id=incident.id,
            actor_id=actor.id,
            event_type="action",
            title="Manual response checklist completed",
            detail=f"Playbook run #{run.id}",
        )
    )
    db.add(
        AuditLog(
            actor_id=actor.id,
            action="playbook.manual_checklist_completed",
            resource=f"{incident_key}:{run_id}",
        )
    )
    db.commit()
    return {"id": run.id, "status": run.status, "execution_mode": run.execution_mode}


@router.get("/incidents/{incident_key}/analysis")
def incident_analysis(
    incident_key: str,
    _: User = Depends(require_permission("incidents:read")),
    db: Session = Depends(get_db),
):
    incident = incident_or_404(db, incident_key)
    asset_keys = db.scalars(
        select(Alert.asset_key).where(
            Alert.incident_id == incident.id, Alert.asset_key.is_not(None)
        )
    ).all()
    telemetry = (
        db.scalars(
            select(TelemetryEvent)
            .where(TelemetryEvent.asset_key.in_(asset_keys))
            .order_by(TelemetryEvent.occurred_at.desc())
            .limit(100)
        ).all()
        if asset_keys
        else []
    )
    findings_count = (
        db.scalar(
            select(func.count())
            .select_from(SecurityFinding)
            .where(SecurityFinding.asset_key.in_(asset_keys))
        )
        or 0
        if asset_keys
        else 0
    )
    evidence_count = (
        db.scalar(
            select(func.count())
            .select_from(IncidentEvidence)
            .where(IncidentEvidence.incident_id == incident.id)
        )
        or 0
    )
    return {
        "mode": "Rule-based analyst assistance",
        "summary": (
            f"{incident.severity} severity incident with risk score {incident.risk_score}, "
            f"currently {incident.status}."
        ),
        "signals_reviewed": len(telemetry),
        "related_findings": findings_count,
        "evidence_items": evidence_count,
        "recommendations": [
            "Review correlated telemetry and attach source evidence.",
            "Confirm incident ownership and current containment status.",
            "Request approval before carrying out any sensitive response action.",
        ],
        "generated_at": datetime.now(timezone.utc),
    }


@router.get("/automation/runs")
def list_automation_runs(
    _: User = Depends(require_permission("incidents:read")),
    db: Session = Depends(get_db),
):
    rows = db.execute(
        select(PlaybookRun, ResponsePlaybook, Incident)
        .join(ResponsePlaybook, PlaybookRun.playbook_id == ResponsePlaybook.id)
        .join(Incident, PlaybookRun.incident_id == Incident.id)
        .order_by(PlaybookRun.created_at.desc())
        .limit(500)
    ).all()
    return [
        {
            "id": run.id,
            "incident_key": incident.incident_key,
            "playbook_key": book.key,
            "playbook": book.name,
            "requested_by": run.requested_by,
            "steps": book.steps,
            "status": run.status,
            "execution_mode": run.execution_mode,
            "approval_note": run.approval_note,
            "created_at": run.created_at,
        }
        for run, book, incident in rows
    ]


@router.post("/automation/runs", status_code=201)
def create_automation_run(
    payload: AutomationRunCreate,
    actor: User = Depends(require_permission("incidents:manage")),
    db: Session = Depends(get_db),
):
    incident = incident_or_404(db, payload.incident_key)
    book = db.scalar(
        select(ResponsePlaybook).where(
            ResponsePlaybook.key == payload.playbook_key,
            ResponsePlaybook.enabled.is_(True),
        )
    )
    if not book:
        raise HTTPException(status_code=404, detail="Response playbook not found")
    run = PlaybookRun(playbook_id=book.id, incident_id=incident.id, requested_by=actor.id)
    db.add(run)
    db.add(
        IncidentEvent(
            incident_id=incident.id,
            actor_id=actor.id,
            event_type="approval",
            title=f"Automation approval requested: {book.name}",
            detail="Manual checklist only. No external response action is executed.",
        )
    )
    db.add(
        AuditLog(
            actor_id=actor.id,
            action="automation.run_requested",
            resource=f"{incident.incident_key}:{book.key}",
        )
    )
    db.commit()
    db.refresh(run)
    return {
        "id": run.id,
        "incident_key": incident.incident_key,
        "playbook": book.name,
        "status": run.status,
        "execution_mode": run.execution_mode,
        "created_at": run.created_at,
    }


@router.post("/automation/runs/{run_id}/decision")
def decide_automation_run(
    run_id: int,
    payload: ResponseActionDecision,
    actor: User = Depends(require_permission("response:approve")),
    db: Session = Depends(get_db),
):
    run = db.scalar(select(PlaybookRun).where(PlaybookRun.id == run_id).with_for_update())
    if not run:
        raise HTTPException(status_code=404, detail="Automation run not found")
    if run.requested_by == actor.id:
        raise HTTPException(status_code=409, detail="A requester cannot approve their own run")
    if run.status != "Pending approval":
        raise HTTPException(status_code=409, detail="Automation run has already been decided")
    run.status = payload.decision
    run.decided_by = actor.id
    run.approval_note = payload.note.strip()
    run.decided_at = datetime.now(timezone.utc)
    incident = db.get(Incident, run.incident_id)
    book = db.get(ResponsePlaybook, run.playbook_id)
    db.add(
        IncidentEvent(
            incident_id=incident.id,
            actor_id=actor.id,
            event_type="approval",
            title=f"Automation run {payload.decision.lower()}: {book.name}",
            detail=run.approval_note,
        )
    )
    db.add(
        AuditLog(
            actor_id=actor.id,
            action=f"automation.{payload.decision.lower()}",
            resource=f"{incident.incident_key}:{run_id}",
        )
    )
    db.commit()
    return {"id": run.id, "status": run.status, "approval_note": run.approval_note}


@router.post("/automation/runs/{run_id}/complete")
def complete_automation_run(
    run_id: int,
    actor: User = Depends(require_permission("incidents:manage")),
    db: Session = Depends(get_db),
):
    run = db.scalar(select(PlaybookRun).where(PlaybookRun.id == run_id).with_for_update())
    if not run:
        raise HTTPException(status_code=404, detail="Automation run not found")
    if run.status != "Approved":
        raise HTTPException(status_code=409, detail="Only an approved run can be completed")
    incident = db.get(Incident, run.incident_id)
    run.status = "Completed"
    db.add(
        IncidentEvent(
            incident_id=incident.id,
            actor_id=actor.id,
            event_type="action",
            title="Manual automation checklist completed",
            detail=f"Playbook run #{run.id} · {incident.incident_key}",
        )
    )
    db.add(
        AuditLog(actor_id=actor.id, action="automation.manual_run_completed", resource=str(run_id))
    )
    db.commit()
    return {"id": run.id, "status": run.status, "execution_mode": run.execution_mode}
