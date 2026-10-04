import base64
import hashlib
import logging
import secrets
import smtplib
from datetime import datetime, timedelta, timezone
from email.message import EmailMessage
from urllib.parse import urlencode, urlsplit

import httpx
import jwt
import pyotp
from fastapi import APIRouter, Depends, HTTPException, Query, status
from fastapi.responses import RedirectResponse
from sqlalchemy import select, update
from sqlalchemy.orm import Session, selectinload

from ..config import settings
from ..database import get_db
from ..dependencies import get_current_user
from ..models import AuditLog, PasswordResetToken, Role, SSOLoginTicket, User
from ..schemas import (
    LoginRequest,
    MfaCode,
    PasswordResetConfirm,
    PasswordResetRequest,
    RegistrationRequest,
    TokenView,
    UserProfileUpdate,
    UserView,
)
from ..security import ALGORITHM, create_access_token, hash_password, verify_password

router = APIRouter(prefix="/api/v1/auth", tags=["auth"])
logger = logging.getLogger(__name__)


def _oidc_configured() -> bool:
    return bool(
        settings.oidc_issuer_url
        and settings.oidc_client_id
        and settings.oidc_client_secret
        and settings.oidc_redirect_uri
    )


@router.get("/sso/status")
def sso_status():
    return {"enabled": _oidc_configured(), "provider": settings.oidc_issuer_url or ""}


@router.get("/config")
def auth_config():
    return {"public_signup_enabled": settings.allow_public_signup}


@router.get("/sso/start")
async def sso_start():
    if not _oidc_configured():
        raise HTTPException(status_code=404, detail="Single sign-on is not configured")
    async with httpx.AsyncClient(timeout=10) as client:
        response = await client.get(
            f"{settings.oidc_issuer_url.rstrip('/')}/.well-known/openid-configuration"
        )
        response.raise_for_status()
        metadata = response.json()
    if metadata.get("issuer", "").rstrip("/") != settings.oidc_issuer_url.rstrip("/"):
        raise HTTPException(
            status_code=502, detail="Identity provider issuer does not match configuration"
        )
    if not metadata.get("authorization_endpoint", "").startswith("https://"):
        raise HTTPException(
            status_code=502, detail="Identity provider authorization endpoint must use HTTPS"
        )
    code_verifier = secrets.token_urlsafe(48)
    code_challenge = (
        base64.urlsafe_b64encode(hashlib.sha256(code_verifier.encode()).digest())
        .rstrip(b"=")
        .decode()
    )
    state = jwt.encode(
        {
            "nonce": secrets.token_urlsafe(24),
            "code_verifier": code_verifier,
            "exp": datetime.now(timezone.utc) + timedelta(minutes=8),
        },
        settings.jwt_secret,
        algorithm=ALGORITHM,
    )
    # The signed state itself contains the nonce; OIDC nonce is also sent to the provider.
    claims = jwt.decode(state, settings.jwt_secret, algorithms=[ALGORITHM])
    from urllib.parse import urlencode

    params = urlencode(
        {
            "client_id": settings.oidc_client_id,
            "response_type": "code",
            "scope": "openid email profile",
            "redirect_uri": settings.oidc_redirect_uri,
            "state": state,
            "nonce": claims["nonce"],
            "code_challenge": code_challenge,
            "code_challenge_method": "S256",
        }
    )
    return {"authorization_url": f"{metadata['authorization_endpoint']}?{params}"}


@router.get("/sso/callback")
async def sso_callback(
    code: str | None = None,
    state: str | None = None,
    error: str | None = None,
    db: Session = Depends(get_db),
):
    if error:
        return RedirectResponse(
            f"{settings.frontend_url.rstrip('/')}?sso_error=login_cancelled", status_code=303
        )
    if not code or not state:
        raise HTTPException(status_code=400, detail="Identity provider response is incomplete")
    if not _oidc_configured():
        raise HTTPException(status_code=404, detail="Single sign-on is not configured")
    try:
        state_claims = jwt.decode(state, settings.jwt_secret, algorithms=[ALGORITHM])
    except jwt.PyJWTError as exc:
        raise HTTPException(status_code=401, detail="SSO state is invalid or expired") from exc
    async with httpx.AsyncClient(timeout=15) as client:
        metadata_response = await client.get(
            f"{settings.oidc_issuer_url.rstrip('/')}/.well-known/openid-configuration"
        )
        metadata_response.raise_for_status()
        metadata = metadata_response.json()
        if metadata.get("issuer", "").rstrip("/") != settings.oidc_issuer_url.rstrip("/"):
            raise HTTPException(
                status_code=502, detail="Identity provider issuer does not match configuration"
            )
        if not metadata.get("token_endpoint", "").startswith("https://") or not metadata.get(
            "jwks_uri", ""
        ).startswith("https://"):
            raise HTTPException(
                status_code=502, detail="Identity provider token and key endpoints must use HTTPS"
            )
        token_response = await client.post(
            metadata["token_endpoint"],
            data={
                "grant_type": "authorization_code",
                "code": code,
                "redirect_uri": settings.oidc_redirect_uri,
                "client_id": settings.oidc_client_id,
                "client_secret": settings.oidc_client_secret,
                "code_verifier": state_claims["code_verifier"],
            },
        )
        if token_response.is_error:
            raise HTTPException(
                status_code=401, detail="Identity provider rejected the sign-in code"
            )
        tokens = token_response.json()
    identity_token = tokens.get("id_token")
    if not identity_token:
        raise HTTPException(status_code=401, detail="Identity provider did not return an ID token")
    signing_key = jwt.PyJWKClient(metadata["jwks_uri"]).get_signing_key_from_jwt(identity_token).key
    try:
        claims = jwt.decode(
            identity_token,
            signing_key,
            algorithms=["RS256", "ES256"],
            audience=settings.oidc_client_id,
            issuer=metadata["issuer"],
            options={"require": ["exp", "iat", "sub", "nonce", "email"]},
        )
    except jwt.PyJWTError as exc:
        raise HTTPException(status_code=401, detail="Identity provider token is invalid") from exc
    if claims.get("nonce") != state_claims.get("nonce"):
        raise HTTPException(status_code=401, detail="SSO nonce validation failed")
    if claims.get("email_verified") not in (True, "true", "True", 1):
        raise HTTPException(status_code=403, detail="The identity provider email must be verified")
    user = db.scalar(select(User).where(User.email == str(claims["email"]).lower()))
    if not user or not user.is_active:
        raise HTTPException(
            status_code=403, detail="This verified account is not provisioned in CipherOps"
        )
    amr = claims.get("amr") or []
    if user.mfa_enabled and "mfa" not in amr:
        raise HTTPException(
            status_code=403, detail="The identity provider must confirm MFA for this account"
        )
    ticket = secrets.token_urlsafe(36)
    db.add(
        SSOLoginTicket(
            token_hash=hashlib.sha256(ticket.encode()).hexdigest(),
            user_id=user.id,
            expires_at=datetime.now(timezone.utc) + timedelta(seconds=60),
        )
    )
    db.add(AuditLog(actor_id=user.id, action="auth.sso_login", resource="oidc"))
    db.commit()
    return RedirectResponse(
        f"{settings.frontend_url.rstrip('/')}?sso_ticket={ticket}", status_code=303
    )


@router.post("/sso/exchange", response_model=TokenView)
def sso_exchange(ticket: str = Query(min_length=20, max_length=128), db: Session = Depends(get_db)):
    digest = hashlib.sha256(ticket.encode()).hexdigest()
    now = datetime.now(timezone.utc)
    claimed = db.execute(
        update(SSOLoginTicket)
        .where(
            SSOLoginTicket.token_hash == digest,
            SSOLoginTicket.consumed_at.is_(None),
            SSOLoginTicket.expires_at > now,
        )
        .values(consumed_at=now)
        .returning(SSOLoginTicket.user_id)
    ).scalar_one_or_none()
    if claimed is None:
        raise HTTPException(status_code=401, detail="SSO sign-in ticket is invalid or expired")
    user = db.scalar(
        select(User)
        .options(selectinload(User.roles).selectinload(Role.permissions))
        .where(User.id == claimed)
    )
    if not user or not user.is_active:
        raise HTTPException(status_code=401, detail="This CipherOps account is unavailable")
    db.commit()
    return TokenView(
        access_token=create_access_token(str(user.id), user.session_version),
        expires_in=settings.jwt_expire_minutes * 60,
        user=user_view(user),
    )


def user_view(user: User) -> UserView:
    name_parts = user.full_name.split(maxsplit=1)
    return UserView(
        id=user.id,
        email=user.email,
        full_name=user.full_name,
        first_name=user.first_name or name_parts[0],
        last_name=user.last_name or (name_parts[1] if len(name_parts) > 1 else ""),
        phone_country=user.phone_country,
        phone_dial_code=user.phone_dial_code,
        mobile_number=user.mobile_number,
        country_code=user.country_code,
        country=user.country,
        city=user.city,
        avatar_data=user.avatar_data,
        roles=[r.name for r in user.roles],
        permissions=sorted({p.key for r in user.roles for p in r.permissions}),
    )


@router.post("/register", response_model=TokenView, status_code=status.HTTP_201_CREATED)
def register(payload: RegistrationRequest, db: Session = Depends(get_db)):
    if not settings.allow_public_signup:
        raise HTTPException(status_code=404, detail="Public sign up is disabled")
    email = str(payload.email).lower()
    if db.scalar(select(User.id).where(User.email == email)):
        raise HTTPException(status_code=409, detail="An account with this email already exists")
    role = db.scalar(select(Role).where(Role.name == "SOC Analyst"))
    if role is None:
        raise HTTPException(status_code=503, detail="Account roles are not initialized yet")
    full_name = f"{payload.first_name.strip()} {payload.last_name.strip()}"
    user = User(
        email=email,
        full_name=full_name,
        first_name=payload.first_name.strip(),
        last_name=payload.last_name.strip(),
        phone_country=payload.phone_country,
        phone_dial_code=payload.phone_dial_code,
        mobile_number=payload.mobile_number,
        country_code=payload.country_code,
        country=payload.country.strip(),
        session_version=0,
        city=payload.city.strip(),
        avatar_data=payload.avatar_data,
        password_hash=hash_password(payload.password),
        roles=[role],
    )
    db.add(user)
    db.flush()
    db.add(AuditLog(actor_id=user.id, action="auth.register", resource=email))
    db.commit()
    return TokenView(
        access_token=create_access_token(str(user.id), user.session_version),
        expires_in=settings.jwt_expire_minutes * 60,
        user=user_view(user),
    )


def _send_password_reset(email: str, reset_url: str) -> None:
    message = EmailMessage()
    message["Subject"] = "Reset your CipherOps password"
    message["From"] = settings.smtp_from_email
    message["To"] = email
    message.set_content(
        "A password reset was requested for your CipherOps account. "
        "This link expires in 20 minutes and can only be used once:\n\n"
        f"{reset_url}\n\nIf you did not request this, ignore this message."
    )
    with smtplib.SMTP(settings.smtp_host, settings.smtp_port, timeout=8) as server:
        server.ehlo()
        if settings.smtp_starttls:
            server.starttls()
            server.ehlo()
        if settings.smtp_username and settings.smtp_password:
            server.login(settings.smtp_username, settings.smtp_password)
        server.send_message(message)


@router.post("/password/forgot")
def password_forgot(payload: PasswordResetRequest, db: Session = Depends(get_db)):
    generic = {"message": "If the account exists, password reset instructions will be sent."}
    user = db.scalar(select(User).where(User.email == str(payload.email).lower()))
    if not user or not user.is_active:
        return generic
    now = datetime.now(timezone.utc)
    recent = db.scalar(
        select(PasswordResetToken.id)
        .where(
            PasswordResetToken.user_id == user.id,
            PasswordResetToken.created_at > now - timedelta(minutes=1),
        )
        .limit(1)
    )
    if recent:
        return generic
    db.execute(
        update(PasswordResetToken)
        .where(
            PasswordResetToken.user_id == user.id,
            PasswordResetToken.consumed_at.is_(None),
        )
        .values(consumed_at=now)
    )
    token = secrets.token_urlsafe(36)
    db.add(
        PasswordResetToken(
            token_hash=hashlib.sha256(token.encode()).hexdigest(),
            user_id=user.id,
            expires_at=now + timedelta(minutes=20),
        )
    )
    db.commit()
    reset_url = f"{settings.frontend_url.rstrip('/')}/?{urlencode({'password_reset': token})}"
    mail_configured = bool(settings.smtp_host and settings.smtp_from_email)
    if mail_configured:
        try:
            _send_password_reset(user.email, reset_url)
        except (OSError, smtplib.SMTPException):
            logger.exception("Password reset email delivery failed")
    elif settings.password_reset_dev_mode and urlsplit(settings.frontend_url).hostname in {
        "localhost",
        "127.0.0.1",
        "::1",
    }:
        generic["development_reset_url"] = reset_url
    return generic


@router.post("/password/reset")
def password_reset(payload: PasswordResetConfirm, db: Session = Depends(get_db)):
    now = datetime.now(timezone.utc)
    user_id = db.execute(
        update(PasswordResetToken)
        .where(
            PasswordResetToken.token_hash == hashlib.sha256(payload.token.encode()).hexdigest(),
            PasswordResetToken.consumed_at.is_(None),
            PasswordResetToken.expires_at > now,
        )
        .values(consumed_at=now)
        .returning(PasswordResetToken.user_id)
    ).scalar_one_or_none()
    if user_id is None:
        db.rollback()
        raise HTTPException(status_code=400, detail="Reset link is invalid or has expired")
    user = db.get(User, user_id)
    if not user or not user.is_active:
        db.rollback()
        raise HTTPException(status_code=400, detail="Reset link is invalid or has expired")
    user.password_hash = hash_password(payload.password)
    user.session_version += 1
    db.add(AuditLog(actor_id=user.id, action="auth.password_reset", resource=user.email))
    db.commit()
    return {"message": "Password updated. Sign in using your new password."}


@router.post("/login", response_model=TokenView)
def login(payload: LoginRequest, db: Session = Depends(get_db)):
    user = db.scalar(
        select(User)
        .options(selectinload(User.roles).selectinload(Role.permissions))
        .where(User.email == payload.email.lower())
    )
    if not user or not user.is_active or not verify_password(payload.password, user.password_hash):
        raise HTTPException(status_code=401, detail="Email or password is incorrect")
    if user.mfa_enabled and (
        not payload.mfa_code
        or not user.mfa_secret
        or not pyotp.TOTP(user.mfa_secret).verify(payload.mfa_code, valid_window=1)
    ):
        raise HTTPException(status_code=401, detail="A valid MFA code is required")
    db.add(AuditLog(actor_id=user.id, action="auth.login", resource="session"))
    db.commit()
    return TokenView(
        access_token=create_access_token(str(user.id), user.session_version),
        expires_in=settings.jwt_expire_minutes * 60,
        user=user_view(user),
    )


@router.get("/me", response_model=UserView)
def me(user: User = Depends(get_current_user)):
    return user_view(user)


@router.patch("/me", response_model=UserView)
def update_me(
    payload: UserProfileUpdate,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    user.first_name = payload.first_name.strip()
    user.last_name = payload.last_name.strip()
    user.full_name = f"{user.first_name} {user.last_name}"
    user.phone_country = payload.phone_country
    user.phone_dial_code = payload.phone_dial_code
    user.mobile_number = payload.mobile_number
    user.country_code = payload.country_code
    user.country = payload.country.strip()
    user.city = payload.city.strip()
    user.avatar_data = payload.avatar_data
    db.add(AuditLog(actor_id=user.id, action="auth.profile_updated", resource=user.email))
    db.commit()
    db.refresh(user)
    return user_view(user)


@router.get("/mfa/status")
def mfa_status(user: User = Depends(get_current_user)):
    return {"enabled": user.mfa_enabled}


@router.post("/mfa/setup")
def mfa_setup(user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    if user.mfa_enabled:
        raise HTTPException(status_code=409, detail="MFA is already enabled")
    secret = pyotp.random_base32()
    user.mfa_secret = secret
    db.add(AuditLog(actor_id=user.id, action="auth.mfa_setup_started", resource=user.email))
    db.commit()
    uri = pyotp.TOTP(secret).provisioning_uri(name=user.email, issuer_name="CipherOps AI")
    return {"secret": secret, "provisioning_uri": uri}


@router.post("/mfa/verify")
def mfa_verify(
    payload: MfaCode, user: User = Depends(get_current_user), db: Session = Depends(get_db)
):
    if not user.mfa_secret or not pyotp.TOTP(user.mfa_secret).verify(payload.code, valid_window=1):
        raise HTTPException(status_code=400, detail="MFA code is not valid")
    user.mfa_enabled = True
    db.add(AuditLog(actor_id=user.id, action="auth.mfa_enabled", resource=user.email))
    db.commit()
    return {"enabled": True}


@router.post("/mfa/disable")
def mfa_disable(
    payload: MfaCode, user: User = Depends(get_current_user), db: Session = Depends(get_db)
):
    if (
        not user.mfa_enabled
        or not user.mfa_secret
        or not pyotp.TOTP(user.mfa_secret).verify(payload.code, valid_window=1)
    ):
        raise HTTPException(status_code=400, detail="MFA code is not valid")
    user.mfa_enabled = False
    user.mfa_secret = None
    db.add(AuditLog(actor_id=user.id, action="auth.mfa_disabled", resource=user.email))
    db.commit()
    return {"enabled": False}
