"""Optional, analyst-triggered VirusTotal reputation lookups."""

import base64
import ipaddress
import re
from urllib.parse import quote, urlsplit

import httpx
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from ..config import settings
from ..database import get_db
from ..dependencies import require_permission
from ..models import AuditLog, User
from ..schemas import ThreatIntelLookup

router = APIRouter(prefix="/api/v1/threat-intel", tags=["threat-intelligence-enrichment"])


@router.get("/provider-status")
def provider_status(_: User = Depends(require_permission("findings:read"))):
    return {
        "provider": "VirusTotal",
        "configured": bool(settings.virustotal_api_key),
        "manual_lookup_only": True,
        "community_sharing_notice": (
            "VirusTotal states that queried indicators are added to its dataset and made "
            "available to its community. Do not query confidential, sensitive or personal data."
        ),
    }


def provider_path(indicator_type: str, value: str) -> str:
    if indicator_type == "ip":
        try:
            address = ipaddress.ip_address(value)
        except ValueError as exc:
            raise HTTPException(
                status_code=422, detail="Enter a valid IPv4 or IPv6 address"
            ) from exc
        return f"ip_addresses/{quote(str(address), safe=':')}"
    if indicator_type == "domain":
        domain = value.rstrip(".").casefold()
        if len(domain) > 253 or not re.fullmatch(
            r"(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}", domain
        ):
            raise HTTPException(status_code=422, detail="Enter a valid public domain name")
        return f"domains/{quote(domain, safe='')}"
    if indicator_type == "hash":
        if not re.fullmatch(r"(?i)(?:[a-f0-9]{32}|[a-f0-9]{40}|[a-f0-9]{64})", value):
            raise HTTPException(status_code=422, detail="Enter an MD5, SHA-1 or SHA-256 hash")
        return f"files/{quote(value.lower(), safe='')}"
    try:
        parts = urlsplit(value)
        if parts.scheme not in {"http", "https"} or not parts.hostname or parts.username:
            raise ValueError
        if len(value) > 2048:
            raise ValueError
        _ = parts.port
    except ValueError as exc:
        raise HTTPException(status_code=422, detail="Enter a valid HTTP or HTTPS URL") from exc
    url_id = base64.urlsafe_b64encode(value.encode()).decode().rstrip("=")
    return f"urls/{url_id}"


@router.post("/enrich")
def enrich_indicator(
    payload: ThreatIntelLookup,
    actor: User = Depends(require_permission("findings:manage")),
    db: Session = Depends(get_db),
):
    if not settings.virustotal_api_key:
        raise HTTPException(status_code=503, detail="VirusTotal is not configured on this server")
    path = provider_path(payload.indicator_type, payload.value.strip())
    try:
        response = httpx.get(
            f"https://www.virustotal.com/api/v3/{path}",
            headers={"x-apikey": settings.virustotal_api_key},
            timeout=settings.virustotal_timeout_seconds,
        )
    except httpx.TimeoutException as exc:
        raise HTTPException(status_code=504, detail="VirusTotal lookup timed out") from exc
    except httpx.RequestError as exc:
        raise HTTPException(status_code=502, detail="VirusTotal could not be reached") from exc
    if response.status_code == 404:
        result = {
            "provider": "VirusTotal",
            "found": False,
            "indicator_type": payload.indicator_type,
        }
    elif response.status_code == 429:
        raise HTTPException(status_code=429, detail="VirusTotal rate limit reached; retry later")
    elif response.status_code in {401, 403}:
        raise HTTPException(status_code=502, detail="VirusTotal rejected the configured server key")
    elif response.is_error:
        raise HTTPException(status_code=502, detail="VirusTotal returned an upstream error")
    else:
        try:
            attributes = response.json()["data"]["attributes"]
        except (ValueError, KeyError, TypeError) as exc:
            raise HTTPException(
                status_code=502, detail="VirusTotal returned an invalid report"
            ) from exc
        stats = attributes.get("last_analysis_stats") or {}
        results = attributes.get("last_analysis_results") or {}
        detections = [
            {"engine": name, "category": item.get("category"), "result": item.get("result")}
            for name, item in results.items()
            if item.get("category") in {"malicious", "suspicious"}
        ][:10]
        result = {
            "provider": "VirusTotal",
            "found": True,
            "indicator_type": payload.indicator_type,
            "reputation": attributes.get("reputation", 0),
            "last_analysis_date": attributes.get("last_analysis_date"),
            "last_analysis_stats": {
                key: stats.get(key, 0)
                for key in ("malicious", "suspicious", "harmless", "undetected", "timeout")
            },
            "malicious_engines": detections,
            "categories": attributes.get("categories", {}),
            "community_shared": True,
        }
    db.add(
        AuditLog(
            actor_id=actor.id,
            action="threat_intel.virustotal_lookup",
            resource=payload.indicator_type,
        )
    )
    db.commit()
    return result
