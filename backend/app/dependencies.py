import jwt
from fastapi import Depends, HTTPException
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy.orm import Session, selectinload

from .config import settings
from .database import get_db
from .models import Role, User
from .security import ALGORITHM

bearer = HTTPBearer(auto_error=False)


def get_current_user(
    credentials: HTTPAuthorizationCredentials | None = Depends(bearer),
    db: Session = Depends(get_db),
) -> User:
    if not credentials:
        raise HTTPException(
            status_code=401,
            detail="Authentication required",
            headers={"WWW-Authenticate": "Bearer"},
        )
    try:
        claims = jwt.decode(
            credentials.credentials, settings.jwt_secret, algorithms=[ALGORITHM]
        )
        subject = claims.get("sub")
    except jwt.PyJWTError as exc:
        raise HTTPException(status_code=401, detail="Invalid or expired token") from exc
    try:
        user_id = int(subject)
    except (ValueError, TypeError) as exc:
        raise HTTPException(status_code=401, detail="Invalid token subject") from exc
    user = (
        db.query(User)
        .options(selectinload(User.roles).selectinload(Role.permissions))
        .filter(User.id == user_id)
        .first()
    )
    if not user or not user.is_active:
        raise HTTPException(status_code=401, detail="User is unavailable")
    if claims.get("ver", 0) != user.session_version:
        raise HTTPException(status_code=401, detail="Session expired; sign in again")
    return user


def require_permission(key: str):
    def check(user: User = Depends(get_current_user)) -> User:
        if not any(permission.key == key for role in user.roles for permission in role.permissions):
            raise HTTPException(status_code=403, detail="Insufficient permissions")
        return user

    return check
