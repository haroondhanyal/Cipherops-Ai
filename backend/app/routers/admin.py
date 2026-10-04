from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import select
from sqlalchemy.orm import Session, selectinload

from ..database import get_db
from ..dependencies import require_permission
from ..models import AuditLog, Role, User
from ..schemas import RoleAssignment, UserCreate, UserStatusUpdate
from ..security import hash_password

router = APIRouter(prefix="/api/v1/admin", tags=["administration"])


@router.get("/roles", dependencies=[Depends(require_permission("admin:manage"))])
def list_roles(db: Session = Depends(get_db)):
    roles = db.scalars(
        select(Role).options(selectinload(Role.permissions)).order_by(Role.name)
    ).all()
    return [
        {
            "name": role.name,
            "description": role.description,
            "permissions": sorted(p.key for p in role.permissions),
        }
        for role in roles
    ]


@router.get("/users", dependencies=[Depends(require_permission("admin:manage"))])
def list_users(db: Session = Depends(get_db)):
    users = db.scalars(select(User).options(selectinload(User.roles)).order_by(User.email)).all()
    return [
        {
            "id": u.id,
            "email": u.email,
            "full_name": u.full_name,
            "is_active": u.is_active,
            "roles": [r.name for r in u.roles],
            "requested_role": u.requested_role,
        }
        for u in users
    ]


@router.post("/users", status_code=201)
def create_user(
    payload: UserCreate,
    actor: User = Depends(require_permission("admin:manage")),
    db: Session = Depends(get_db),
):
    email = str(payload.email).lower()
    if db.scalar(select(User.id).where(User.email == email)):
        raise HTTPException(status_code=409, detail="A user with this email already exists")
    role = db.scalar(
        select(Role).options(selectinload(Role.permissions)).where(Role.name == payload.role)
    )
    if not role:
        raise HTTPException(status_code=422, detail="Unknown role")
    user = User(
        email=email,
        full_name=payload.full_name.strip(),
        password_hash=hash_password(payload.password),
        roles=[role],
    )
    db.add(user)
    db.flush()
    db.add(AuditLog(actor_id=actor.id, action="admin.user_created", resource=email))
    db.commit()
    return {
        "id": user.id,
        "email": user.email,
        "full_name": user.full_name,
        "is_active": user.is_active,
        "roles": [role.name],
    }


@router.patch("/users/{user_id}")
def update_user_status(
    user_id: int,
    payload: UserStatusUpdate,
    actor: User = Depends(require_permission("admin:manage")),
    db: Session = Depends(get_db),
):
    target = db.get(User, user_id)
    if not target:
        raise HTTPException(status_code=404, detail="User not found")
    if target.id == actor.id and not payload.is_active:
        raise HTTPException(status_code=422, detail="You cannot deactivate your own account")
    target.is_active = payload.is_active
    db.add(AuditLog(actor_id=actor.id, action="admin.user_status_changed", resource=target.email))
    db.commit()
    return {"id": target.id, "email": target.email, "is_active": target.is_active}


@router.patch("/users/{user_id}/role")
def assign_user_role(
    user_id: int,
    payload: RoleAssignment,
    actor: User = Depends(require_permission("admin:manage")),
    db: Session = Depends(get_db),
):
    target = db.scalar(select(User).options(selectinload(User.roles)).where(User.id == user_id))
    if not target:
        raise HTTPException(status_code=404, detail="User not found")
    role = db.scalar(
        select(Role).options(selectinload(Role.permissions)).where(Role.name == payload.role)
    )
    if not role:
        raise HTTPException(status_code=422, detail="Unknown role")
    if target.id == actor.id and not any(
        permission.key == "admin:manage" for permission in role.permissions
    ):
        raise HTTPException(
            status_code=422, detail="You cannot remove your own administrator access"
        )
    target.roles = [role]
    target.requested_role = role.name
    db.add(
        AuditLog(
            actor_id=actor.id,
            action="admin.user_role_assigned",
            resource=f"{target.email}:{role.name}",
        )
    )
    db.commit()
    return {"id": target.id, "email": target.email, "roles": [role.name]}


@router.get("/audit-logs", dependencies=[Depends(require_permission("admin:manage"))])
def list_audit_logs(limit: int = Query(default=100, ge=1, le=500), db: Session = Depends(get_db)):
    logs = db.scalars(select(AuditLog).order_by(AuditLog.created_at.desc()).limit(limit)).all()
    return [
        {
            "id": row.id,
            "actor_id": row.actor_id,
            "action": row.action,
            "resource": row.resource,
            "created_at": row.created_at.isoformat(),
        }
        for row in logs
    ]
