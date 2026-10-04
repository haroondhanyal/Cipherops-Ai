"""Permission-aware workspace search across operational records."""

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import or_, select
from sqlalchemy.orm import Session

from ..database import get_db
from ..dependencies import get_current_user
from ..models import Alert, Asset, Incident, SecurityFinding, User

router = APIRouter(prefix="/api/v1", tags=["workspace-search"])


def permission_set(user: User) -> set[str]:
    return {permission.key for role in user.roles for permission in role.permissions}


@router.get("/search")
def search_workspace(
    q: str = Query(min_length=2, max_length=100),
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    query = q.strip()
    if len(query) < 2:
        raise HTTPException(status_code=422, detail="Enter at least two search characters")
    escaped_query = query.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
    pattern = f"%{escaped_query}%"
    permissions = permission_set(user)
    results = []

    if "incidents:read" in permissions:
        incidents = db.scalars(
            select(Incident)
            .where(
                or_(
                    Incident.incident_key.ilike(pattern, escape="\\"),
                    Incident.title.ilike(pattern, escape="\\"),
                    Incident.owner.ilike(pattern, escape="\\"),
                )
            )
            .order_by(Incident.updated_at.desc())
            .limit(5)
        ).all()
        results.extend(
            {
                "kind": "incident",
                "key": row.incident_key,
                "title": row.title,
                "subtitle": f"{row.severity} · {row.status} · owner {row.owner}",
            }
            for row in incidents
        )

    if "alerts:read" in permissions:
        alerts = db.scalars(
            select(Alert)
            .where(
                or_(
                    Alert.alert_key.ilike(pattern, escape="\\"),
                    Alert.title.ilike(pattern, escape="\\"),
                    Alert.source.ilike(pattern, escape="\\"),
                    Alert.asset_key.ilike(pattern, escape="\\"),
                )
            )
            .order_by(Alert.last_seen.desc())
            .limit(5)
        ).all()
        results.extend(
            {
                "kind": "alert",
                "key": row.alert_key,
                "title": row.title,
                "subtitle": f"{row.severity} · {row.status} · {row.source}",
            }
            for row in alerts
        )

    if "assets:read" in permissions:
        assets = db.scalars(
            select(Asset)
            .where(
                or_(
                    Asset.asset_key.ilike(pattern, escape="\\"),
                    Asset.name.ilike(pattern, escape="\\"),
                    Asset.owner.ilike(pattern, escape="\\"),
                    Asset.provider.ilike(pattern, escape="\\"),
                )
            )
            .order_by(Asset.risk_score.desc())
            .limit(5)
        ).all()
        results.extend(
            {
                "kind": "asset",
                "key": row.asset_key,
                "title": row.name,
                "subtitle": f"{row.provider} · {row.criticality} risk · {row.asset_key}",
            }
            for row in assets
        )

    if "findings:read" in permissions:
        findings = db.scalars(
            select(SecurityFinding)
            .where(
                or_(
                    SecurityFinding.external_id.ilike(pattern, escape="\\"),
                    SecurityFinding.title.ilike(pattern, escape="\\"),
                    SecurityFinding.asset_key.ilike(pattern, escape="\\"),
                )
            )
            .order_by(SecurityFinding.risk_score.desc())
            .limit(5)
        ).all()
        results.extend(
            {
                "kind": "finding",
                "key": str(row.id),
                "domain": row.domain,
                "title": row.title,
                "subtitle": f"{row.severity} · {row.status} · {row.domain}",
            }
            for row in findings
        )

    return results
