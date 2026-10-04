"""Compliance control evidence and durable report snapshots."""

import csv
import io
from collections import defaultdict
from datetime import datetime, timedelta, timezone
from statistics import mean, median

from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import StreamingResponse
from sqlalchemy import func, or_, select
from sqlalchemy.orm import Session

from ..database import get_db
from ..dependencies import require_permission
from ..models import (
    Alert,
    Asset,
    AuditLog,
    ComplianceControl,
    ControlEvidence,
    Incident,
    IncidentEvent,
    ReportSnapshot,
    SecurityFinding,
    TelemetryEvent,
    User,
)
from ..schemas import ComplianceControlUpdate, ControlEvidenceCreate, ReportCreate

router = APIRouter(prefix="/api/v1", tags=["governance"])


def flatten_report(data: dict) -> list[dict[str, str]]:
    rows: list[dict[str, str]] = []

    def walk(value, path: str):
        if isinstance(value, dict):
            for key, child in value.items():
                if key == "items":
                    continue
                walk(child, f"{path}.{key}" if path else key)
        elif isinstance(value, list):
            for index, child in enumerate(value):
                identity = child.get("date", index) if isinstance(child, dict) else index
                walk(child, f"{path}.{identity}")
        elif value is not None:
            rows.append({"field": path, "value": str(value)})

    walk(data, "")
    return rows


def csv_safe(value: object) -> str:
    text_value = str(value if value is not None else "")
    if text_value.lstrip().startswith(("=", "+", "-", "@", "\t", "\r")):
        return "'" + text_value
    return text_value


def snapshot_data(report_type: str, db: Session, period_days: int = 30) -> dict:
    generated = datetime.now(timezone.utc)
    now = generated.isoformat()
    if report_type == "executive":
        cutoff = generated - timedelta(days=period_days)
        statuses = (
            "New",
            "Triaged",
            "Acknowledged",
            "Investigating",
            "Contained",
            "Resolved",
            "Closed",
        )
        status_counts = {
            status: db.scalar(
                select(func.count()).select_from(Incident).where(Incident.status == status)
            )
            or 0
            for status in statuses
        }
        daily = {
            (generated - timedelta(days=offset)).date().isoformat(): {
                "date": (generated - timedelta(days=offset)).date().isoformat(),
                "incidents_opened": 0,
                "incidents_resolved": 0,
                "alerts_created": 0,
            }
            for offset in reversed(range(period_days))
        }
        period_incident_dates = db.scalars(
            select(Incident.created_at).where(Incident.created_at >= cutoff)
        ).all()
        for stamp in period_incident_dates:
            if stamp.tzinfo is None:
                stamp = stamp.replace(tzinfo=timezone.utc)
            day = stamp.date().isoformat()
            if day in daily:
                daily[day]["incidents_opened"] += 1
        period_alert_dates = db.scalars(
            select(Alert.created_at).where(Alert.created_at >= cutoff)
        ).all()
        for stamp in period_alert_dates:
            if stamp.tzinfo is None:
                stamp = stamp.replace(tzinfo=timezone.utc)
            day = stamp.date().isoformat()
            if day in daily:
                daily[day]["alerts_created"] += 1

        transition_ids = db.scalars(
            select(IncidentEvent.incident_id)
            .where(
                IncidentEvent.event_type == "action",
                IncidentEvent.created_at >= cutoff,
                or_(
                    IncidentEvent.detail.ilike("%status: Resolved%"),
                    IncidentEvent.detail.ilike("%status: Closed%"),
                ),
            )
            .distinct()
        ).all()
        closed = db.scalars(
            select(Incident).where(
                Incident.status.in_(["Resolved", "Closed"]),
                or_(Incident.updated_at >= cutoff, Incident.id.in_(transition_ids)),
            )
        ).all()
        resolved_total = (
            db.scalar(
                select(func.count())
                .select_from(Incident)
                .where(Incident.status.in_(["Resolved", "Closed"]))
            )
            or 0
        )
        closed_ids = [row.id for row in closed]
        resolution_events = (
            db.scalars(
                select(IncidentEvent)
                .where(
                    IncidentEvent.incident_id.in_(closed_ids), IncidentEvent.event_type == "action"
                )
                .order_by(IncidentEvent.created_at.asc())
            ).all()
            if closed_ids
            else []
        )
        resolved_at: dict[int, datetime] = {}
        for event in resolution_events:
            if (
                "status: resolved" in event.detail.casefold()
                or "status: closed" in event.detail.casefold()
            ):
                resolved_at[event.incident_id] = event.created_at
        resolution_hours = []
        resolution_by_severity: dict[str, list[float]] = defaultdict(list)
        for incident in closed:
            finished = resolved_at.get(incident.id, incident.updated_at)
            start = incident.created_at
            if start.tzinfo is None:
                start = start.replace(tzinfo=timezone.utc)
            if finished.tzinfo is None:
                finished = finished.replace(tzinfo=timezone.utc)
            if finished < cutoff:
                continue
            elapsed = (finished - start).total_seconds() / 3600
            if elapsed >= 0:
                resolution_hours.append(elapsed)
                resolution_by_severity[incident.severity].append(elapsed)
            day = finished.date().isoformat()
            if day in daily:
                daily[day]["incidents_resolved"] += 1
        total_open_alerts = (
            db.scalar(
                select(func.count())
                .select_from(Alert)
                .where(Alert.status.not_in(["Resolved", "Suppressed"]))
            )
            or 0
        )
        critical_assets = (
            db.scalar(
                select(func.count()).select_from(Asset).where(Asset.criticality == "Critical")
            )
            or 0
        )
        high_risk_findings = (
            db.scalar(
                select(func.count())
                .select_from(SecurityFinding)
                .where(SecurityFinding.risk_score >= 70, SecurityFinding.status != "Resolved")
            )
            or 0
        )
        controls = db.scalars(select(ComplianceControl)).all()
        frameworks: dict[str, dict[str, int]] = defaultdict(lambda: {"total": 0, "compliant": 0})
        for control in controls:
            frameworks[control.framework]["total"] += 1
            frameworks[control.framework]["compliant"] += int(
                control.status in {"Compliant", "Not applicable"}
            )
        framework_scores = {
            name: round(item["compliant"] * 100 / item["total"]) if item["total"] else 0
            for name, item in sorted(frameworks.items())
        }
        telemetry_volume = (
            db.scalar(
                select(func.count())
                .select_from(TelemetryEvent)
                .where(TelemetryEvent.received_at >= cutoff)
            )
            or 0
        )
        severity_counts = {
            severity: db.scalar(
                select(func.count())
                .select_from(Incident)
                .where(
                    Incident.severity == severity, Incident.status.not_in(["Resolved", "Closed"])
                )
            )
            or 0
            for severity in ("Critical", "High", "Medium", "Low")
        }
        avg_open_risk = db.scalar(
            select(func.avg(Incident.risk_score)).where(
                Incident.status.not_in(["Resolved", "Closed"])
            )
        )
        return {
            "generated_at": now,
            "period_days": period_days,
            "period_started_at": cutoff.isoformat(),
            "incidents": status_counts,
            "incidents_opened_in_period": len(period_incident_dates),
            "incidents_resolved_total": resolved_total,
            "incidents_resolved_in_period": len(resolution_hours),
            "resolution_time_hours": {
                "mean": round(mean(resolution_hours), 2) if resolution_hours else None,
                "median": round(median(resolution_hours), 2) if resolution_hours else None,
                "sample_size": len(resolution_hours),
                "basis": (
                    "Incident creation to first recorded Resolved/Closed status; "
                    "updated_at fallback when no transition event exists."
                ),
            },
            "resolution_time_hours_by_severity": {
                severity: {
                    "mean": round(mean(values), 2),
                    "sample_size": len(values),
                }
                for severity, values in sorted(resolution_by_severity.items())
            },
            "open_incidents_by_severity": severity_counts,
            "average_open_incident_risk_score": round(float(avg_open_risk), 2)
            if avg_open_risk is not None
            else None,
            "alerts_open": total_open_alerts,
            "critical_assets": critical_assets,
            "high_risk_findings": high_risk_findings,
            "telemetry_events_in_period": telemetry_volume,
            "compliance_framework_scores": framework_scores,
            "daily_trends": list(daily.values()),
        }
    if report_type == "incident":
        rows = db.scalars(select(Incident).order_by(Incident.created_at.desc()).limit(500)).all()
        return {
            "generated_at": now,
            "items": [
                {
                    "key": r.incident_key,
                    "title": r.title,
                    "severity": r.severity,
                    "risk_score": r.risk_score,
                    "status": r.status,
                    "owner": r.owner,
                    "created_at": r.created_at.isoformat(),
                }
                for r in rows
            ],
        }
    if report_type == "asset-risk":
        rows = db.scalars(select(Asset).order_by(Asset.risk_score.desc()).limit(1000)).all()
        return {
            "generated_at": now,
            "items": [
                {
                    "asset_key": r.asset_key,
                    "name": r.name,
                    "provider": r.provider,
                    "environment": r.environment,
                    "criticality": r.criticality,
                    "risk_score": r.risk_score,
                    "owner": r.owner,
                    "status": r.status,
                }
                for r in rows
            ],
        }
    controls = db.scalars(
        select(ComplianceControl).order_by(
            ComplianceControl.framework, ComplianceControl.control_key
        )
    ).all()
    return {
        "generated_at": now,
        "items": [
            {
                "framework": r.framework,
                "control_key": r.control_key,
                "title": r.title,
                "status": r.status,
                "owner": r.owner,
            }
            for r in controls
        ],
    }


@router.get("/compliance/summary")
def compliance_summary(
    _: User = Depends(require_permission("compliance:read")), db: Session = Depends(get_db)
):
    rows = db.execute(
        select(ComplianceControl.framework, ComplianceControl.status, func.count()).group_by(
            ComplianceControl.framework, ComplianceControl.status
        )
    ).all()
    result: dict[str, dict] = {}
    for framework, status, count in rows:
        item = result.setdefault(framework, {"total": 0, "compliant": 0, "open": 0})
        item["total"] += count
        item["compliant"] += count if status in {"Compliant", "Not applicable"} else 0
        item["open"] += count if status not in {"Compliant", "Not applicable"} else 0
    return [
        {
            "framework": key,
            **values,
            "score": round(values["compliant"] / values["total"] * 100) if values["total"] else 0,
        }
        for key, values in sorted(result.items())
    ]


@router.get("/compliance/controls")
def list_controls(
    framework: str | None = None,
    _: User = Depends(require_permission("compliance:read")),
    db: Session = Depends(get_db),
):
    statement = select(ComplianceControl).order_by(
        ComplianceControl.framework, ComplianceControl.control_key
    )
    if framework:
        statement = statement.where(ComplianceControl.framework == framework)
    rows = db.scalars(statement.limit(1000)).all()
    counts = dict(
        db.execute(
            select(ControlEvidence.control_id, func.count()).group_by(ControlEvidence.control_id)
        ).all()
    )
    return [
        {
            "id": row.id,
            "framework": row.framework,
            "control_key": row.control_key,
            "title": row.title,
            "description": row.description,
            "status": row.status,
            "owner": row.owner,
            "evidence_count": counts.get(row.id, 0),
            "updated_at": row.updated_at,
        }
        for row in rows
    ]


@router.patch("/compliance/controls/{control_id}")
def update_control(
    control_id: int,
    payload: ComplianceControlUpdate,
    actor: User = Depends(require_permission("compliance:manage")),
    db: Session = Depends(get_db),
):
    control = db.get(ComplianceControl, control_id)
    if not control:
        raise HTTPException(status_code=404, detail="Compliance control not found")
    control.status = payload.status
    if payload.owner is not None:
        control.owner = payload.owner.strip()
    db.add(
        AuditLog(
            actor_id=actor.id,
            action="compliance.control_updated",
            resource=f"{control.framework}:{control.control_key}",
        )
    )
    db.commit()
    return {
        "id": control.id,
        "status": control.status,
        "owner": control.owner,
        "updated_at": control.updated_at,
    }


@router.get("/compliance/controls/{control_id}/evidence")
def list_control_evidence(
    control_id: int,
    _: User = Depends(require_permission("compliance:read")),
    db: Session = Depends(get_db),
):
    if not db.get(ComplianceControl, control_id):
        raise HTTPException(status_code=404, detail="Compliance control not found")
    rows = db.scalars(
        select(ControlEvidence)
        .where(ControlEvidence.control_id == control_id)
        .order_by(ControlEvidence.created_at.desc())
    ).all()
    return [
        {
            "id": r.id,
            "title": r.title,
            "source_uri": r.source_uri,
            "sha256": r.sha256,
            "notes": r.notes,
            "created_at": r.created_at,
        }
        for r in rows
    ]


@router.post("/compliance/controls/{control_id}/evidence", status_code=201)
def add_control_evidence(
    control_id: int,
    payload: ControlEvidenceCreate,
    actor: User = Depends(require_permission("compliance:manage")),
    db: Session = Depends(get_db),
):
    control = db.get(ComplianceControl, control_id)
    if not control:
        raise HTTPException(status_code=404, detail="Compliance control not found")
    evidence = ControlEvidence(control_id=control.id, added_by=actor.id, **payload.model_dump())
    db.add(evidence)
    db.add(
        AuditLog(
            actor_id=actor.id,
            action="compliance.evidence_added",
            resource=f"{control.framework}:{control.control_key}",
        )
    )
    db.commit()
    db.refresh(evidence)
    return {
        "id": evidence.id,
        "title": evidence.title,
        "source_uri": evidence.source_uri,
        "sha256": evidence.sha256,
        "notes": evidence.notes,
        "created_at": evidence.created_at,
    }


@router.get("/reports")
def list_reports(
    _: User = Depends(require_permission("reports:read")), db: Session = Depends(get_db)
):
    rows = db.scalars(
        select(ReportSnapshot).order_by(ReportSnapshot.created_at.desc()).limit(200)
    ).all()
    return [
        {
            "id": r.id,
            "report_type": r.report_type,
            "title": r.title,
            "created_at": r.created_at,
            "row_count": len(r.data["items"]) if "items" in r.data else len(flatten_report(r.data)),
        }
        for r in rows
    ]


@router.post("/reports", status_code=201)
def create_report(
    payload: ReportCreate,
    actor: User = Depends(require_permission("reports:manage")),
    db: Session = Depends(get_db),
):
    snapshot = ReportSnapshot(
        report_type=payload.report_type,
        title=payload.title.strip(),
        created_by=actor.id,
        data=snapshot_data(payload.report_type, db, payload.period_days),
    )
    db.add(snapshot)
    db.flush()
    db.add(AuditLog(actor_id=actor.id, action="report.generated", resource=str(snapshot.id)))
    db.commit()
    db.refresh(snapshot)
    return {
        "id": snapshot.id,
        "report_type": snapshot.report_type,
        "title": snapshot.title,
        "data": snapshot.data,
        "created_at": snapshot.created_at,
    }


@router.get("/reports/{report_id}")
def get_report(
    report_id: int,
    _: User = Depends(require_permission("reports:read")),
    db: Session = Depends(get_db),
):
    report = db.get(ReportSnapshot, report_id)
    if not report:
        raise HTTPException(status_code=404, detail="Report not found")
    return {
        "id": report.id,
        "report_type": report.report_type,
        "title": report.title,
        "data": report.data,
        "created_at": report.created_at,
    }


@router.get("/reports/{report_id}/csv")
def download_report(
    report_id: int,
    actor: User = Depends(require_permission("reports:read")),
    db: Session = Depends(get_db),
):
    report = db.get(ReportSnapshot, report_id)
    if not report:
        raise HTTPException(status_code=404, detail="Report not found")
    data = report.data
    rows = data.get("items")
    if rows is None:
        rows = flatten_report(data)
    output = io.StringIO()
    if rows:
        writer = csv.DictWriter(output, fieldnames=list(rows[0].keys()), extrasaction="ignore")
        writer.writeheader()
        writer.writerows([{key: csv_safe(value) for key, value in row.items()} for row in rows])
    db.add(AuditLog(actor_id=actor.id, action="report.downloaded", resource=str(report.id)))
    db.commit()
    filename = f"cipherops-{report.report_type}-{report.id}.csv"
    return StreamingResponse(
        iter([output.getvalue()]),
        media_type="text/csv",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )
