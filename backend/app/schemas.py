from datetime import datetime, timezone

from pydantic import BaseModel, ConfigDict, EmailStr, Field, model_validator


class LoginRequest(BaseModel):
    email: EmailStr
    password: str = Field(min_length=1, max_length=256)
    mfa_code: str | None = Field(default=None, pattern="^\\d{6}$")


class RegistrationRequest(BaseModel):
    email: EmailStr
    first_name: str = Field(min_length=1, max_length=75)
    last_name: str = Field(min_length=1, max_length=75)
    phone_country: str = Field(pattern="^[A-Z]{2}$")
    phone_dial_code: str = Field(pattern="^\\+[1-9]\\d{0,3}$")
    mobile_number: str = Field(pattern="^\\d{6,15}$")
    country_code: str = Field(pattern="^[A-Z]{2}$")
    country: str = Field(min_length=2, max_length=100)
    city: str = Field(min_length=1, max_length=120)
    password: str = Field(min_length=12, max_length=256)
    confirm_password: str = Field(min_length=12, max_length=256)
    avatar_data: str | None = Field(
        default=None,
        max_length=400_000,
        pattern="^data:image/(jpeg|png|webp);base64,[A-Za-z0-9+/]+={0,2}$",
    )

    @model_validator(mode="after")
    def validate_password_confirmation(self):
        if self.password != self.confirm_password:
            raise ValueError("Passwords do not match")
        return self


class UserProfileUpdate(BaseModel):
    first_name: str = Field(min_length=1, max_length=75)
    last_name: str = Field(min_length=1, max_length=75)
    phone_country: str = Field(pattern="^[A-Z]{2}$")
    phone_dial_code: str = Field(pattern="^\\+[1-9]\\d{0,3}$")
    mobile_number: str = Field(pattern="^\\d{6,15}$")
    country_code: str = Field(pattern="^[A-Z]{2}$")
    country: str = Field(min_length=2, max_length=100)
    city: str = Field(min_length=1, max_length=120)
    avatar_data: str | None = Field(
        default=None,
        max_length=400_000,
        pattern="^data:image/(jpeg|png|webp);base64,[A-Za-z0-9+/]+={0,2}$",
    )


class PasswordResetRequest(BaseModel):
    email: EmailStr


class PasswordResetConfirm(BaseModel):
    token: str = Field(min_length=24, max_length=128)
    password: str = Field(min_length=12, max_length=256)
    confirm_password: str = Field(min_length=12, max_length=256)

    @model_validator(mode="after")
    def validate_password_confirmation(self):
        if self.password != self.confirm_password:
            raise ValueError("Passwords do not match")
        return self


class MfaCode(BaseModel):
    code: str = Field(pattern="^\\d{6}$")


class UserCreate(BaseModel):
    email: EmailStr
    full_name: str = Field(min_length=2, max_length=160)
    password: str = Field(min_length=12, max_length=256)
    role: str = Field(default="SOC Analyst", min_length=2, max_length=80)


class UserStatusUpdate(BaseModel):
    is_active: bool


class IncidentCreate(BaseModel):
    title: str = Field(min_length=8, max_length=240)
    severity: str = Field(pattern="^(Critical|High|Medium|Low)$")
    risk_score: int = Field(ge=0, le=100)
    source: str = Field(default="Analyst created", max_length=80)
    asset_count: int = Field(default=1, ge=1, le=100000)


class IncidentUpdate(BaseModel):
    status: str | None = Field(
        default=None, pattern="^(New|Triaged|Acknowledged|Investigating|Contained|Resolved|Closed)$"
    )
    owner: str | None = Field(default=None, min_length=2, max_length=320)
    severity: str | None = Field(default=None, pattern="^(Critical|High|Medium|Low)$")
    risk_score: int | None = Field(default=None, ge=0, le=100)


class IncidentEventCreate(BaseModel):
    event_type: str = Field(default="note", pattern="^(note|action|approval|evidence)$")
    title: str = Field(min_length=2, max_length=160)
    detail: str = Field(default="", max_length=4000)


class AlertUpdate(BaseModel):
    status: str | None = Field(
        default=None, pattern="^(New|Acknowledged|Investigating|Resolved|Suppressed)$"
    )
    assigned_to: str | None = Field(default=None, min_length=2, max_length=320)


class IntegrationCreate(BaseModel):
    name: str = Field(min_length=2, max_length=120)
    provider: str = Field(min_length=2, max_length=80)


class IntegrationStatusUpdate(BaseModel):
    is_active: bool


class TelemetryAssetInput(BaseModel):
    asset_key: str = Field(min_length=1, max_length=240)
    name: str = Field(min_length=1, max_length=240)
    asset_type: str = Field(default="Unknown", max_length=80)
    environment: str = Field(default="Unknown", max_length=80)
    provider: str = Field(default="Unknown", max_length=80)
    region: str = Field(default="Unknown", max_length=120)
    owner: str = Field(default="Unassigned", max_length=320)
    criticality: str = Field(default="Medium", pattern="^(Critical|High|Medium|Low)$")
    risk_score: int = Field(default=0, ge=0, le=100)
    attributes: dict = Field(default_factory=dict)


class SecurityFindingInput(BaseModel):
    domain: str = Field(pattern="^(cloud|identity|vulnerability|agent|threat)$")
    external_id: str = Field(min_length=1, max_length=240)
    title: str = Field(min_length=2, max_length=240)
    description: str = Field(default="", max_length=4000)
    severity: str = Field(pattern="^(Critical|High|Medium|Low)$")
    risk_score: int = Field(ge=0, le=100)
    asset_key: str | None = Field(default=None, max_length=240)
    attributes: dict = Field(default_factory=dict)

    @model_validator(mode="after")
    def validate_threat_indicator(self):
        if self.domain == "threat":
            value = self.attributes.get("value") or self.attributes.get("indicator")
            indicator_type = self.attributes.get("indicator_type")
            if not isinstance(value, str) or not value.strip():
                raise ValueError("Threat indicators require attributes.value")
            value = value.strip()
            if len(value) > 240:
                raise ValueError("Threat indicator values are limited to 240 characters")
            value = value.casefold()
            self.attributes["value"] = value
            self.external_id = value
            if indicator_type not in {"ip", "domain", "url", "hash", "email", "other"}:
                raise ValueError("Threat indicators require a supported indicator_type")
            confidence = self.attributes.get("confidence", self.risk_score)
            if confidence is None:
                confidence = self.risk_score
            if (
                isinstance(confidence, bool)
                or not isinstance(confidence, (int, float))
                or not 0 <= confidence <= 100
            ):
                raise ValueError("Threat indicator confidence must be between 0 and 100")
            self.attributes["confidence"] = int(round(confidence))
        return self


class TelemetryInput(BaseModel):
    external_id: str = Field(min_length=1, max_length=240)
    event_type: str = Field(min_length=1, max_length=100)
    severity: str = Field(
        default="Informational", pattern="^(Critical|High|Medium|Low|Informational)$"
    )
    summary: str = Field(min_length=1, max_length=1000)
    occurred_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    asset: TelemetryAssetInput | None = None
    findings: list[SecurityFindingInput] = Field(default_factory=list, max_length=100)
    attributes: dict = Field(default_factory=dict)


class TelemetryBatch(BaseModel):
    events: list[TelemetryInput] = Field(min_length=1, max_length=500)


class SecurityFindingUpdate(BaseModel):
    status: str | None = Field(default=None, pattern="^(Open|In progress|Accepted risk|Resolved)$")
    owner: str | None = Field(default=None, min_length=2, max_length=320)


class EvidenceCreate(BaseModel):
    evidence_type: str = Field(default="link", pattern="^(link|hash|note|event|file-reference)$")
    title: str = Field(min_length=2, max_length=240)
    source_uri: str = Field(default="", max_length=2000)
    sha256: str | None = Field(default=None, pattern="^[a-fA-F0-9]{64}$")
    notes: str = Field(default="", max_length=4000)


class ResponseActionCreate(BaseModel):
    action: str = Field(min_length=3, max_length=160)
    scope: str = Field(default="", max_length=4000)


class ResponseActionDecision(BaseModel):
    decision: str = Field(pattern="^(Approved|Rejected)$")
    note: str = Field(default="", max_length=2000)


class PlaybookRunCreate(BaseModel):
    playbook_key: str = Field(min_length=2, max_length=80)


class AutomationRunCreate(BaseModel):
    incident_key: str = Field(min_length=4, max_length=32)
    playbook_key: str = Field(min_length=2, max_length=80)


class ComplianceControlUpdate(BaseModel):
    status: str = Field(
        pattern="^(Not assessed|In progress|Compliant|Non-compliant|Not applicable)$"
    )
    owner: str | None = Field(default=None, min_length=2, max_length=320)


class ControlEvidenceCreate(BaseModel):
    title: str = Field(min_length=2, max_length=240)
    source_uri: str = Field(default="", max_length=2000)
    sha256: str | None = Field(default=None, pattern="^[a-fA-F0-9]{64}$")
    notes: str = Field(default="", max_length=4000)


class ReportCreate(BaseModel):
    report_type: str = Field(pattern="^(executive|incident|compliance|asset-risk)$")
    title: str = Field(min_length=3, max_length=240)


class UserView(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: int
    email: str
    full_name: str
    first_name: str
    last_name: str
    phone_country: str | None = None
    phone_dial_code: str | None = None
    mobile_number: str | None = None
    country_code: str | None = None
    country: str | None = None
    city: str | None = None
    avatar_data: str | None = None
    roles: list[str]
    permissions: list[str]


class TokenView(BaseModel):
    access_token: str
    token_type: str = "bearer"
    expires_in: int
    user: UserView


class IncidentView(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    incident_key: str
    title: str
    severity: str
    risk_score: int
    status: str
    source: str
    asset_count: int
    owner: str
    created_at: datetime
    updated_at: datetime | None = None


class IncidentEventView(BaseModel):
    id: int
    event_type: str
    title: str
    detail: str
    actor: str
    created_at: datetime


class AlertView(BaseModel):
    id: int
    alert_key: str
    title: str
    description: str
    severity: str
    status: str
    source: str
    external_id: str | None
    asset_key: str | None
    assigned_to: str
    first_seen: datetime
    last_seen: datetime


class AssetView(BaseModel):
    asset_key: str
    name: str
    asset_type: str
    environment: str
    provider: str
    region: str
    owner: str
    criticality: str
    risk_score: int
    status: str
    attributes: dict
    first_seen: datetime
    last_seen: datetime


class TelemetryIngestResult(BaseModel):
    accepted: int
    duplicates: int
    alerts_created: int
    assets_upserted: int
