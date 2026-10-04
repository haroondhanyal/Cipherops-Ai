"""Create fictional workspace accounts, incidents, alerts, telemetry and assets."""

import hashlib
from datetime import datetime, timedelta, timezone
from getpass import getpass

from sqlalchemy import select

from .database import SessionLocal
from .models import Alert, Asset, Incident, Role, TelemetryEvent, User
from .security import hash_password

DEMO_USERS = [
    ("raja.jamal@northstar.example", "Raja Haroon Jamal", "SOC Analyst"),
    ("admin@northstar.example", "Northstar Security Admin", "Security Administrator"),
    ("ciso@northstar.example", "Northstar CISO", "CISO"),
    ("amina.khan@northstar.example", "Amina Khan", "Cloud Security Engineer"),
    ("sara.ali@northstar.example", "Sara Ali", "Compliance Officer"),
]
DEMO_ASSETS = [
    (
        "aws:i-0northstarapi",
        "prod-api-01",
        "Compute instance",
        "Production",
        "AWS",
        "eu-west-1",
        "Platform team",
        "High",
        76,
    ),
    (
        "aws:s3:prod-backups",
        "prod-backups",
        "Object storage",
        "Production",
        "AWS",
        "eu-west-1",
        "Cloud team",
        "Critical",
        94,
    ),
    (
        "gcp:sql:finance-db-02",
        "finance-db-02",
        "Database",
        "Production",
        "GCP",
        "us-central1",
        "Data team",
        "High",
        68,
    ),
    (
        "entra:user:john.doe",
        "john.doe@northstar.example",
        "Identity",
        "Corporate",
        "Entra ID",
        "Global",
        "Finance",
        "High",
        82,
    ),
    (
        "aws:role:admin",
        "production-admin-role",
        "IAM role",
        "Production",
        "AWS",
        "Global",
        "Cloud team",
        "Critical",
        88,
    ),
]
DEMO_ALERTS = [
    (
        "ALR-DEMO000001",
        "Suspicious Cloud Access and Data Exfiltration",
        "Critical",
        "CloudTrail",
        "evt-cloud-001",
        "aws:s3:prod-backups",
    ),
    (
        "ALR-DEMO000002",
        "Privileged account impossible travel",
        "High",
        "Entra ID",
        "evt-id-002",
        "entra:user:john.doe",
    ),
    (
        "ALR-DEMO000003",
        "Unusual outbound traffic to rare domain",
        "High",
        "Network analytics",
        "evt-net-003",
        "aws:i-0northstarapi",
    ),
    (
        "ALR-DEMO000004",
        "Excessive privilege assigned to service role",
        "High",
        "AWS Config",
        "evt-iam-004",
        "aws:role:admin",
    ),
    (
        "ALR-DEMO000005",
        "Unexpected database export activity",
        "Critical",
        "GCP Audit Logs",
        "evt-db-005",
        "gcp:sql:finance-db-02",
    ),
]
INCIDENTS = [
    (
        "INC-1024",
        "Suspicious Cloud Access and Data Exfiltration",
        "Critical",
        92,
        "Investigating",
        "CloudTrail",
        8,
        "raja.jamal@northstar.example",
    ),
    (
        "INC-1023",
        "Privileged account impossible travel",
        "High",
        84,
        "Investigating",
        "Identity protection",
        3,
        "raja.jamal@northstar.example",
    ),
    (
        "INC-1022",
        "Unusual outbound traffic to rare domain",
        "High",
        78,
        "Triaged",
        "Network analytics",
        4,
        "amina.khan@northstar.example",
    ),
    (
        "INC-1021",
        "Endpoint malware behavior detected",
        "Medium",
        61,
        "Triaged",
        "Endpoint detection",
        2,
        "raja.jamal@northstar.example",
    ),
    (
        "INC-1020",
        "Repeated MFA fatigue attempts",
        "Medium",
        58,
        "New",
        "Identity protection",
        1,
        "Unassigned",
    ),
    (
        "INC-1019",
        "Public storage bucket discovered",
        "Critical",
        91,
        "Investigating",
        "Cloud posture",
        5,
        "amina.khan@northstar.example",
    ),
    (
        "INC-1018",
        "Suspicious OAuth application consent",
        "High",
        81,
        "Triaged",
        "Identity protection",
        2,
        "raja.jamal@northstar.example",
    ),
    (
        "INC-1017",
        "Possible API key exposure in repository",
        "High",
        76,
        "New",
        "Secret scanning",
        3,
        "Unassigned",
    ),
    (
        "INC-1016",
        "Unusual database export activity",
        "Critical",
        89,
        "Investigating",
        "Database audit",
        3,
        "raja.jamal@northstar.example",
    ),
    (
        "INC-1015",
        "Repeated failed VPN authentication",
        "Low",
        29,
        "Closed",
        "Network analytics",
        1,
        "amina.khan@northstar.example",
    ),
    (
        "INC-1014",
        "Suspicious PowerShell execution",
        "High",
        73,
        "Triaged",
        "Endpoint detection",
        2,
        "raja.jamal@northstar.example",
    ),
    (
        "INC-1013",
        "Excessive privilege assigned to service role",
        "High",
        79,
        "Investigating",
        "Cloud posture",
        2,
        "amina.khan@northstar.example",
    ),
    (
        "INC-1012",
        "Potential phishing message reported",
        "Medium",
        55,
        "Triaged",
        "Email security",
        4,
        "raja.jamal@northstar.example",
    ),
    (
        "INC-1011",
        "Unexpected admin console access",
        "High",
        82,
        "New",
        "Identity protection",
        2,
        "Unassigned",
    ),
    (
        "INC-1010",
        "Container image with critical CVE",
        "Critical",
        94,
        "Investigating",
        "Vulnerability scanner",
        6,
        "amina.khan@northstar.example",
    ),
    (
        "INC-1009",
        "New forwarding rule on executive mailbox",
        "High",
        75,
        "Triaged",
        "Email security",
        1,
        "raja.jamal@northstar.example",
    ),
    (
        "INC-1008",
        "Unapproved cloud region resource",
        "Medium",
        52,
        "Closed",
        "Cloud posture",
        2,
        "amina.khan@northstar.example",
    ),
    (
        "INC-1007",
        "Potential lateral movement between servers",
        "High",
        87,
        "Investigating",
        "Endpoint detection",
        7,
        "raja.jamal@northstar.example",
    ),
    (
        "INC-1006",
        "Expired TLS certificate on public service",
        "Low",
        22,
        "Triaged",
        "Attack surface monitor",
        1,
        "Unassigned",
    ),
    (
        "INC-1005",
        "Unusual agent tool invocation",
        "Medium",
        66,
        "New",
        "AI policy monitor",
        2,
        "raja.jamal@northstar.example",
    ),
]


def main():
    password = getpass("Password for seeded demo accounts (12+ characters): ")
    if len(password) < 12:
        raise SystemExit("Choose at least 12 characters")
    with SessionLocal() as db:
        roles = {r.name: r for r in db.scalars(select(Role)).all()}
        missing = sorted({role for _, _, role in DEMO_USERS} - roles.keys())
        if missing:
            raise SystemExit("Run the API once to initialize roles first: " + ", ".join(missing))
        password_digest = hash_password(password)
        for email, name, role in DEMO_USERS:
            if not db.scalar(select(User.id).where(User.email == email)):
                db.add(
                    User(
                        email=email,
                        full_name=name,
                        password_hash=password_digest,
                        roles=[roles[role]],
                    )
                )
        now = datetime.now(timezone.utc)
        for index, (key, title, severity, score, status, source, asset_count, owner) in enumerate(
            INCIDENTS
        ):
            if not db.scalar(select(Incident.id).where(Incident.incident_key == key)):
                db.add(
                    Incident(
                        incident_key=key,
                        title=title,
                        severity=severity,
                        risk_score=score,
                        status=status,
                        source=source,
                        asset_count=asset_count,
                        owner=owner,
                        created_at=now - timedelta(minutes=index * 7),
                    )
                )
        for asset_key, name, kind, env, provider, region, owner, criticality, risk in DEMO_ASSETS:
            if not db.get(Asset, asset_key):
                db.add(
                    Asset(
                        asset_key=asset_key,
                        name=name,
                        asset_type=kind,
                        environment=env,
                        provider=provider,
                        region=region,
                        owner=owner,
                        criticality=criticality,
                        risk_score=risk,
                        status="Active",
                        attributes={"demo": True},
                    )
                )
        for index, (key, title, severity, source, external_id, asset_key) in enumerate(DEMO_ALERTS):
            fingerprint = hashlib.sha256(f"demo|{external_id}".encode()).hexdigest()
            if not db.scalar(select(Alert.id).where(Alert.alert_key == key)):
                db.add(
                    Alert(
                        alert_key=key,
                        fingerprint=fingerprint,
                        title=title,
                        description=title,
                        severity=severity,
                        status="New",
                        source=source,
                        external_id=external_id,
                        asset_key=asset_key,
                        assigned_to="Unassigned",
                        first_seen=now - timedelta(minutes=index * 12),
                        last_seen=now - timedelta(minutes=index * 3),
                    )
                )
            if not db.scalar(
                select(TelemetryEvent.id).where(
                    TelemetryEvent.source == source, TelemetryEvent.external_id == external_id
                )
            ):
                db.add(
                    TelemetryEvent(
                        source=source,
                        external_id=external_id,
                        event_type="detection",
                        severity=severity,
                        summary=title,
                        asset_key=asset_key,
                        occurred_at=now - timedelta(minutes=index * 3),
                        payload={"demo": True},
                    )
                )
        db.commit()
    print(
        f"Seeded {len(DEMO_USERS)} fictional user accounts and "
        f"{len(INCIDENTS)} fictional incidents, {len(DEMO_ALERTS)} alerts, "
        f"{len(DEMO_ASSETS)} assets and {len(DEMO_ALERTS)} telemetry events."
    )
    print("All demo accounts use the password you entered.")
    for email, _, role in DEMO_USERS:
        print(f"  {email} — {role}")


if __name__ == "__main__":
    main()
