"""Compliance control evidence and durable report snapshots."""

import csv
import io
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import StreamingResponse
from sqlalchemy import func, select
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
    ReportSnapshot,
    SecurityFinding,
    User,
)
from ..schemas import ComplianceControlUpdate, ControlEvidenceCreate, ReportCreate

router = APIRouter(prefix="/api/v1", tags=["governance"])


def snapshot_data(report_type: str, db: Session) -> dict:
    now = datetime.now(timezone.utc).isoformat()
    if report_type == "executive":
        return {
            "generated_at": now,
            "incidents": {
                status: db.scalar(
                    select(func.count()).select_from(Incident).where(Incident.status == status)
                )
                or 0
                for status in (
                    "New",
                    "Triaged",
                    "Acknowledged",
                    "Investigating",
                    "Contained",
                    "Resolved",
                    "Closed",
                )
            },
            "alerts_open": db.scalar(
                select(func.count())
                .select_from(Alert)
                .where(Alert.status.not_in(["Resolved", "Suppressed"]))
            )
            or 0,
            "critical_assets": db.scalar(
                select(func.count()).select_from(Asset).where(Asset.criticality == "Critical")
            )
            or 0,
            "high_risk_findings": db.scalar(
                select(func.count())
                .select_from(SecurityFinding)
                .where(SecurityFinding.risk_score >= 70, SecurityFinding.status != "Resolved")
            )
            or 0,
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
            "row_count": len(r.data.get("items", [key for key in r.data if key != "generated_at"])),
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
        data=snapshot_data(payload.report_type, db),
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
        rows = [
            {"metric": key, "value": value} for key, value in data.items() if key != "generated_at"
        ]
    output = io.StringIO()
    if rows:
        writer = csv.DictWriter(output, fieldnames=list(rows[0].keys()), extrasaction="ignore")
        writer.writeheader()
        writer.writerows(rows)
    db.add(AuditLog(actor_id=actor.id, action="report.downloaded", resource=str(report.id)))
    db.commit()
    filename = f"cipherops-{report.report_type}-{report.id}.csv"
    return StreamingResponse(
        iter([output.getvalue()]),
        media_type="text/csv",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )
