"""Create fictional workspace accounts, incidents, alerts, telemetry and assets."""

import hashlib
from datetime import datetime, timedelta, timezone
from getpass import getpass

from sqlalchemy import select

from .database import SessionLocal
from .models import (
    Alert,
    Asset,
    AuditLog,
    ComplianceControl,
    ControlEvidence,
    Incident,
    IncidentEvent,
    IncidentEvidence,
    Integration,
    PlaybookRun,
    ReportSnapshot,
    ResponseAction,
    ResponsePlaybook,
    Role,
    SecurityFinding,
    TelemetryEvent,
    User,
    YaraRule,
)
from .security import hash_password

DEMO_USERS = [
    ("raja.jamal@northstar.example", "Raja Haroon Jamal", "SOC Analyst"),
    ("soc.analyst.02@northstar.example", "Morgan Brooks", "SOC Analyst"),
    ("soc.analyst.03@northstar.example", "Lina Park", "SOC Analyst"),
    ("soc.analyst.04@northstar.example", "Omar Farooq", "SOC Analyst"),
    ("admin@northstar.example", "Northstar Security Admin", "Security Administrator"),
    ("security.admin.02@northstar.example", "Nadia Rahman", "Security Administrator"),
    ("security.admin.03@northstar.example", "Ethan Cole", "Security Administrator"),
    ("security.admin.04@northstar.example", "Maya Chen", "Security Administrator"),
    ("ciso@northstar.example", "Northstar CISO", "CISO"),
    ("ciso.02@northstar.example", "Elena Torres", "CISO"),
    ("ciso.03@northstar.example", "David Kim", "CISO"),
    ("ciso.04@northstar.example", "Aisha Malik", "CISO"),
    ("amina.khan@northstar.example", "Amina Khan", "Cloud Security Engineer"),
    ("cloud.engineer.02@northstar.example", "Noah Patel", "Cloud Security Engineer"),
    ("cloud.engineer.03@northstar.example", "Zara Ahmed", "Cloud Security Engineer"),
    ("cloud.engineer.04@northstar.example", "Leo Martin", "Cloud Security Engineer"),
    ("sara.ali@northstar.example", "Sara Ali", "Compliance Officer"),
    ("compliance.02@northstar.example", "Grace Wilson", "Compliance Officer"),
    ("compliance.03@northstar.example", "Bilal Hussain", "Compliance Officer"),
    ("compliance.04@northstar.example", "Priya Shah", "Compliance Officer"),
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

ALERT_TITLES = [
    "Unusual workload identity token exchange",
    "Endpoint persistence mechanism detected",
    "Sensitive object access burst observed",
    "New privileged application credential created",
    "Outbound traffic to newly registered domain",
    "Unpatched container image deployed to production",
    "Repeated password spray attempts detected",
    "Database snapshot shared outside the organization",
    "Cloud firewall opened to the public internet",
    "Suspicious scheduled task on finance endpoint",
    "Service principal granted directory-wide access",
    "Large archive uploaded to unsanctioned storage",
    "Critical package vulnerability in build pipeline",
    "Unusual administrator session from unmanaged device",
    "Agent requested access to restricted data source",
]

FINDING_DOMAINS = {
    "cloud": ("Cloud posture", "Cloud"),
    "identity": ("Identity monitor", "Identity"),
    "vulnerability": ("Vulnerability scanner", "Vulnerability"),
    "agent": ("AI policy monitor", "AI agent"),
    "threat": ("Threat intelligence feed", "Indicator"),
}

EXTRA_CONTROLS = [
    ("ISO 27001", "A.8.16", "Monitoring activities"),
    ("ISO 27001", "A.8.23", "Web filtering"),
    ("SOC 2", "CC5.2", "Risk identification"),
    ("SOC 2", "CC8.1", "Change management"),
    ("NIST CSF", "ID.AM-02", "Software and service inventory"),
    ("NIST CSF", "PR.DS-01", "Data at rest protection"),
    ("CIS v8", "4.1", "Secure configuration process"),
    ("CIS v8", "13.1", "Central security event alerting"),
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
            user = db.scalar(select(User).where(User.email == email))
            if user is None:
                db.add(
                    User(
                        email=email,
                        full_name=name,
                        password_hash=password_digest,
                        roles=[roles[role]],
                    )
                )
            else:
                user.password_hash = password_digest
                user.roles = [roles[role]]
        analysts = db.scalars(
            select(User).where(
                User.email.in_(["raja.jamal@northstar.example", "admin@northstar.example"])
            )
        ).all()
        actor_by_email = {user.email: user for user in analysts}
        analyst = actor_by_email["raja.jamal@northstar.example"]
        admin = actor_by_email["admin@northstar.example"]
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
        extra_assets = [
            (
                f"demo:{('aws', 'azure', 'gcp')[index % 3]}:workload-{index:02d}",
                f"workload-{index:02d}",
                ("Compute instance", "Database", "Container service")[index % 3],
                ("Production", "Corporate", "Development")[index % 3],
                ("AWS", "Azure", "GCP")[index % 3],
                ("us-east-1", "eastus", "europe-west1")[index % 3],
                ("Platform team", "Identity team", "Data team")[index % 3],
                ("Critical", "High", "Medium", "Low")[index % 4],
                (95 - index * 3) % 100,
            )
            for index in range(6, 21)
        ]
        all_assets = DEMO_ASSETS + extra_assets
        for asset_key, name, kind, env, provider, region, owner, criticality, risk in all_assets:
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
        extra_alerts = [
            (
                f"ALR-DEMO{index:06d}",
                title,
                ("Critical", "High", "Medium", "Low")[index % 4],
                ("CloudTrail", "Entra ID", "Endpoint EDR", "Vulnerability scanner")[index % 4],
                f"evt-demo-{index:03d}",
                all_assets[index % len(all_assets)][0],
            )
            for index, title in enumerate(ALERT_TITLES, start=6)
        ]
        all_alerts = DEMO_ALERTS + extra_alerts
        for index, (key, title, severity, source, external_id, asset_key) in enumerate(all_alerts):
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
                        event_type=(
                            "detection"
                            if index < len(DEMO_ALERTS)
                            else ("identity.signin", "network.connection", "cloud.audit")[index % 3]
                        ),
                        severity=severity,
                        summary=title,
                        asset_key=asset_key,
                        occurred_at=now - timedelta(minutes=index * 3),
                        payload=(
                            {"demo": True}
                            if index < len(DEMO_ALERTS)
                            else {"demo": True, "latitude": 24.86, "longitude": 67.01}
                        ),
                    )
                )

        demo_yara_rules = [
            (
                "Northstar_Suspicious_Cloud_Exfiltration",
                "Detects cloud data-access and exfiltration phrases in ingested event records.",
                """rule Northstar_Suspicious_Cloud_Exfiltration {
  meta:
    description = "Suspicious cloud data movement"
    author = "Northstar SOC"
  strings:
    $exfil = "data exfiltration" nocase
    $export = "database export" nocase
  condition:
    any of them
}""",
                "Critical",
            ),
            (
                "Northstar_Encoded_PowerShell",
                "Looks for common encoded PowerShell launch markers in process telemetry.",
                """rule Northstar_Encoded_PowerShell {
  meta:
    description = "Encoded PowerShell command line"
    author = "Northstar SOC"
  strings:
    $powershell = "powershell" nocase
    $encoded = "-enc" nocase
  condition:
    $powershell and $encoded
}""",
                "High",
            ),
        ]
        for name, description, source, severity in demo_yara_rules:
            if not db.scalar(select(YaraRule.id).where(YaraRule.name == name)):
                db.add(
                    YaraRule(
                        name=name,
                        namespace="northstar_demo",
                        description=description,
                        source=source,
                        severity=severity,
                        created_by=analyst.id,
                    )
                )

        for index, (framework, control_key, title) in enumerate(EXTRA_CONTROLS, start=13):
            exists = db.scalar(
                select(ComplianceControl.id).where(
                    ComplianceControl.framework == framework,
                    ComplianceControl.control_key == control_key,
                )
            )
            if exists is None:
                db.add(
                    ComplianceControl(
                        framework=framework,
                        control_key=control_key,
                        title=title,
                        description="Demo control for security assurance and audit review.",
                        status=("Compliant", "In progress", "Not assessed")[index % 3],
                        owner=("Security team", "Platform team", "Compliance team")[index % 3],
                    )
                )

        db.flush()
        controls = db.scalars(
            select(ComplianceControl).order_by(ComplianceControl.framework, ComplianceControl.id)
        ).all()
        for index, control in enumerate(controls[:10], start=1):
            title = f"Demo evidence package {index:02d}"
            if not db.scalar(
                select(ControlEvidence.id).where(
                    ControlEvidence.control_id == control.id, ControlEvidence.title == title
                )
            ):
                db.add(
                    ControlEvidence(
                        control_id=control.id,
                        added_by=admin.id,
                        title=title,
                        source_uri=f"https://evidence.northstar.example/control/{index:02d}",
                        sha256=hashlib.sha256(title.encode()).hexdigest(),
                        notes="Fictional evidence reference for the seeded workspace.",
                    )
                )

        domain_rows = {
            "cloud": [
                "Public object storage access",
                "Unencrypted production database",
                "Overly permissive workload role",
                "Unrestricted inbound security group",
                "Cloud audit retention below policy",
                "Unmanaged public compute endpoint",
                "Cross-account snapshot sharing",
                "Unrotated service credential",
                "Disabled threat detection region",
                "Unrestricted serverless egress",
            ],
            "identity": [
                "Privileged account without phishing-resistant MFA",
                "Dormant administrator account",
                "Legacy authentication still enabled",
                "Service principal has broad directory access",
                "Unusual sign-in from unmanaged device",
                "Excessive OAuth consent permissions",
                "Stale guest account retains access",
                "Conditional access policy exception",
                "High-risk password reset event",
                "Privileged session outside normal region",
            ],
            "vulnerability": [
                "Critical package in production container",
                "Unsupported operating system on endpoint",
                "Internet-facing service missing security patch",
                "Dependency with known remote exploit",
                "Outdated TLS library on public gateway",
                "High-risk kernel vulnerability on server",
                "Unpatched browser on privileged workstation",
                "Exposed development dependency dashboard",
                "Container base image past support date",
                "Critical library version in build artifact",
            ],
            "agent": [
                "Agent attempted access to restricted data",
                "Unapproved tool invocation observed",
                "Prompt injection pattern in retrieved content",
                "Agent output included sensitive data markers",
                "Unreviewed model endpoint configured",
                "Agent used an excessive token budget",
                "Tool scope exceeds assigned task",
                "Untrusted plugin requested secret access",
                "Policy bypass attempt in agent conversation",
                "Agent audit logging is incomplete",
            ],
            "threat": [
                "Suspicious command-and-control domain",
                "Known phishing host in message telemetry",
                "Malware delivery URL reported by feed",
                "Credential theft infrastructure indicator",
                "Ransomware staging domain observed",
                "Botnet callback address in network event",
                "Lookalike sign-in domain registered",
                "Malicious file hash in endpoint telemetry",
                "Exploit delivery host in proxy records",
                "Threat feed flagged suspicious sender",
            ],
        }
        for domain, titles in domain_rows.items():
            source, label = FINDING_DOMAINS[domain]
            for index, title in enumerate(titles, start=1):
                external_id = f"DEMO-{domain.upper()}-{index:03d}"
                exists = db.scalar(
                    select(SecurityFinding.id).where(
                        SecurityFinding.domain == domain,
                        SecurityFinding.source == source,
                        SecurityFinding.external_id == external_id,
                    )
                )
                if exists is not None:
                    continue
                status = ("Open", "In progress", "Accepted risk", "Resolved")[(index - 1) % 4]
                attributes = {"demo": True, "domain_label": label}
                if domain == "threat":
                    value = f"indicator-{index:02d}.demo-threat.example"
                    attributes.update(
                        {
                            "value": value,
                            "indicator_type": "domain",
                            "confidence": 65 + index * 3,
                        }
                    )
                db.add(
                    SecurityFinding(
                        domain=domain,
                        external_id=external_id,
                        title=title,
                        description=f"Fictional {label.lower()} security finding for demo review.",
                        severity=("Critical", "High", "Medium", "Low")[(index - 1) % 4],
                        status=status,
                        source=source,
                        asset_key=all_assets[(index - 1) % len(all_assets)][0],
                        owner=("Unassigned", "Cloud team", "Security team", "Platform team")[
                            (index - 1) % 4
                        ],
                        risk_score=95 - index * 4,
                        attributes=attributes,
                        first_seen=now - timedelta(days=index),
                        last_seen=now - timedelta(hours=index),
                    )
                )

        integration_providers = [
            "AWS CloudTrail",
            "Microsoft Entra ID",
            "CrowdStrike Falcon",
            "Microsoft Defender",
            "Google Cloud Audit Logs",
            "Wiz CSPM",
            "Tenable Vulnerability Management",
            "Okta System Log",
            "GitHub Audit Log",
            "AI Gateway Monitor",
        ]
        for index, provider in enumerate(integration_providers, start=1):
            name = f"DEMO-{provider}"
            if not db.scalar(select(Integration.id).where(Integration.name == name)):
                demo_digest = hashlib.sha256(f"inactive-demo-key-{index}".encode()).hexdigest()
                db.add(
                    Integration(
                        name=name,
                        provider=provider,
                        token_hash=demo_digest,
                        token_prefix="demo_revoked",
                        is_active=False,
                        created_at=now - timedelta(days=index * 2),
                        last_ingested_at=now - timedelta(hours=index),
                    )
                )

        db.flush()
        incidents = db.scalars(select(Incident).order_by(Incident.incident_key.desc())).all()
        books = db.scalars(select(ResponsePlaybook).order_by(ResponsePlaybook.key)).all()
        for index in range(4, 11):
            key = f"demo_review_{index:02d}"
            book = db.scalar(select(ResponsePlaybook).where(ResponsePlaybook.key == key))
            if book is None:
                book = ResponsePlaybook(
                    key=key,
                    name=(
                        "Email account containment checklist"
                        if index % 2 == 0
                        else "Endpoint isolation review checklist"
                    )
                    + f" {index:02d}",
                    description="Fictional manual review steps for a demo incident.",
                    steps=[
                        "Confirm the affected account or asset",
                        "Preserve relevant investigation evidence",
                        "Get a separate operator approval before containment",
                        "Record the review and owner follow-up",
                    ],
                )
                db.add(book)
                books.append(book)
        db.flush()
        books = db.scalars(select(ResponsePlaybook).order_by(ResponsePlaybook.key)).all()
        for index, incident in enumerate(incidents[:20], start=1):
            event_title = f"Demo investigation update {index:02d}"
            if not db.scalar(
                select(IncidentEvent.id).where(
                    IncidentEvent.incident_id == incident.id,
                    IncidentEvent.title == event_title,
                )
            ):
                db.add(
                    IncidentEvent(
                        incident_id=incident.id,
                        actor_id=analyst.id,
                        event_type="note",
                        title=event_title,
                        detail=(
                            "Initial evidence review completed; follow-up assigned to the owner."
                        ),
                        created_at=incident.created_at + timedelta(minutes=12),
                    )
                )
            if index <= 10:
                evidence_title = f"Demo evidence reference {index:02d}"
                if not db.scalar(
                    select(IncidentEvidence.id).where(
                        IncidentEvidence.incident_id == incident.id,
                        IncidentEvidence.title == evidence_title,
                    )
                ):
                    db.add(
                        IncidentEvidence(
                            incident_id=incident.id,
                            added_by=analyst.id,
                            evidence_type="link",
                            title=evidence_title,
                            source_uri=f"https://evidence.northstar.example/incident/{index:02d}",
                            sha256=hashlib.sha256(evidence_title.encode()).hexdigest(),
                            notes="Fictional reference only; no external evidence is linked.",
                        )
                    )
                action_title = f"Demo containment request {index:02d}"
                if not db.scalar(
                    select(ResponseAction.id).where(
                        ResponseAction.incident_id == incident.id,
                        ResponseAction.action == action_title,
                    )
                ):
                    action_status = ("Pending", "Approved", "Rejected", "Pending", "Approved")[
                        (index - 1) % 5
                    ]
                    db.add(
                        ResponseAction(
                            incident_id=incident.id,
                            requested_by=analyst.id,
                            decided_by=admin.id if action_status != "Pending" else None,
                            action=action_title,
                            scope="Demo-only review scope; no infrastructure action is executed.",
                            status=action_status,
                            decision_detail=(
                                "Reviewed by a separate demo administrator."
                                if action_status != "Pending"
                                else ""
                            ),
                            created_at=now - timedelta(hours=index),
                            decided_at=(
                                now - timedelta(minutes=index * 5)
                                if action_status != "Pending"
                                else None
                            ),
                        )
                    )
                playbook = books[(index - 1) % len(books)]
                if not db.scalar(
                    select(PlaybookRun.id).where(
                        PlaybookRun.incident_id == incident.id,
                        PlaybookRun.playbook_id == playbook.id,
                    )
                ):
                    run_status = ("Pending approval", "Approved", "Completed", "Rejected")[
                        (index - 1) % 4
                    ]
                    db.add(
                        PlaybookRun(
                            playbook_id=playbook.id,
                            incident_id=incident.id,
                            requested_by=analyst.id,
                            decided_by=admin.id if run_status != "Pending approval" else None,
                            status=run_status,
                            approval_note=(
                                "Demo review recorded by a separate approver."
                                if run_status != "Pending approval"
                                else ""
                            ),
                            created_at=now - timedelta(hours=index),
                            decided_at=(
                                now - timedelta(minutes=index * 4)
                                if run_status != "Pending approval"
                                else None
                            ),
                        )
                    )

        from .routers.governance import snapshot_data

        db.flush()
        report_types = ["executive", "incident", "asset-risk", "compliance"]
        for index in range(1, 11):
            report_type = report_types[(index - 1) % len(report_types)]
            title = f"Demo {report_type} snapshot {index:02d}"
            if not db.scalar(select(ReportSnapshot.id).where(ReportSnapshot.title == title)):
                db.add(
                    ReportSnapshot(
                        report_type=report_type,
                        title=title,
                        created_by=admin.id,
                        data=snapshot_data(report_type, db),
                        created_at=now - timedelta(hours=index * 3),
                    )
                )

        for index in range(1, 21):
            resource = f"DEMO-DATASET-{index:03d}"
            if not db.scalar(
                select(AuditLog.id).where(
                    AuditLog.action == "demo.dataset_recorded", AuditLog.resource == resource
                )
            ):
                db.add(
                    AuditLog(
                        actor_id=admin.id,
                        action="demo.dataset_recorded",
                        resource=resource,
                        created_at=now - timedelta(minutes=index * 9),
                    )
                )
        db.commit()
    print(
        f"Seeded {len(DEMO_USERS)} users, {len(INCIDENTS)} incidents, "
        f"{len(all_alerts)} alerts, {len(all_assets)} assets, "
        f"{len(all_alerts)} telemetry events, "
        f"{sum(len(titles) for titles in domain_rows.values())} findings across five domains, "
        f"{len(controls)} compliance controls, {len(books)} playbooks, "
        "10 evidence records, 10 response requests, 10 playbook runs, "
        "10 saved reports and 10 demo integrations."
    )
    print("All seeded demo accounts use the password you entered.")
    for email, _, role in DEMO_USERS:
        print(f"  {email} — {role}")


if __name__ == "__main__":
    main()
