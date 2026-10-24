"""IP and file-hash reputation lookups.

Three sources, picked by INTEL_MODE:
  fixtures  data/intel_fixtures.json. Deterministic, no keys. Evals use this so a
            score change reflects the prompt or model, not drifting threat intel.
  live      AbuseIPDB and VirusTotal free APIs, cached in Postgres (intel_cache).
  auto      live when the API key for that service is set, otherwise fixtures.
"""

from __future__ import annotations

import ipaddress
import json
import re
from datetime import UTC, datetime, timedelta
from functools import lru_cache

import httpx

from app.config import DATA_DIR, get_settings

SHA256_RE = re.compile(r"^[a-fA-F0-9]{64}$")


@lru_cache
def _fixtures() -> dict:
    path = DATA_DIR / "intel_fixtures.json"
    return json.loads(path.read_text()) if path.exists() else {"ips": {}, "hashes": {}}


def _mode(key: str | None) -> str:
    mode = get_settings().intel_mode
    if mode == "auto":
        return "live" if key else "fixtures"
    return mode


# ------------------------------------------------------------------ cache --- #
def _cache_get(kind: str, key: str) -> dict | None:
    try:
        from app.db import SessionLocal
        from app.models import IntelCache

        with SessionLocal() as s:
            row = s.get(IntelCache, (kind, key))
            if not row:
                return None
            fetched = row.fetched_at if row.fetched_at.tzinfo else row.fetched_at.replace(tzinfo=UTC)
            if datetime.now(UTC) - fetched > timedelta(hours=get_settings().intel_cache_ttl_hours):
                return None
            return row.value
    except Exception:  # cache is best-effort; never fail a lookup because of it
        return None


def _cache_put(kind: str, key: str, value: dict) -> None:
    try:
        from app.db import SessionLocal
        from app.models import IntelCache

        with SessionLocal() as s:
            s.merge(IntelCache(kind=kind, key=key, value=value, fetched_at=datetime.now(UTC)))
            s.commit()
    except Exception:
        pass


# --------------------------------------------------------------------- IP --- #
def ip_reputation(ip: str) -> dict:
    ip = ip.strip()
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return {"ip": ip, "error": "not a valid IP address"}

    settings = get_settings()
    mode = _mode(settings.abuseipdb_api_key)

    if mode == "fixtures":
        hit = _fixtures()["ips"].get(ip)
        if hit:
            return {"ip": ip, "source": "fixture", **hit}
        if addr.is_private or addr.is_loopback:
            return {"ip": ip, "source": "local", "is_private": True,
                    "note": "Internal/private address. No public reputation data; judge by host context."}
        return {"ip": ip, "source": "fixture", "abuse_confidence_score": 0, "total_reports": 0,
                "note": "No reports found for this IP."}

    if addr.is_private or addr.is_loopback:
        return {"ip": ip, "source": "local", "is_private": True,
                "note": "Internal/private address. No public reputation data; judge by host context."}

    cached = _cache_get("ip", ip)
    if cached:
        return {**cached, "cached": True}

    resp = httpx.get(
        "https://api.abuseipdb.com/api/v2/check",
        params={"ipAddress": ip, "maxAgeInDays": 90},
        headers={"Key": settings.abuseipdb_api_key or "", "Accept": "application/json"},
        timeout=10,
    )
    if resp.status_code == 429:
        return {"ip": ip, "error": "AbuseIPDB rate limit reached; reputation unknown"}
    resp.raise_for_status()
    d = resp.json()["data"]
    result = {
        "ip": ip, "source": "abuseipdb",
        "abuse_confidence_score": d.get("abuseConfidenceScore"),
        "country": d.get("countryCode"), "isp": d.get("isp"), "usage_type": d.get("usageType"),
        "total_reports": d.get("totalReports"), "is_tor": d.get("isTor"),
        "last_reported_at": d.get("lastReportedAt"),
    }
    _cache_put("ip", ip, result)
    return result


# ------------------------------------------------------------------- hash --- #
def file_hash_reputation(sha256: str) -> dict:
    sha256 = sha256.strip().lower()
    if not SHA256_RE.match(sha256):
        return {"sha256": sha256, "error": "expected a 64-character SHA-256 hex digest"}

    settings = get_settings()
    if _mode(settings.virustotal_api_key) == "fixtures":
        hit = _fixtures()["hashes"].get(sha256)
        if hit:
            return {"sha256": sha256, "source": "fixture", **_hash_summary(hit)}
        return {"sha256": sha256, "source": "fixture", "found": False,
                "note": "Hash not seen by VirusTotal. Unknown, not necessarily safe."}

    cached = _cache_get("hash", sha256)
    if cached:
        return {**cached, "cached": True}

    resp = httpx.get(f"https://www.virustotal.com/api/v3/files/{sha256}",
                     headers={"x-apikey": settings.virustotal_api_key or ""}, timeout=15)
    if resp.status_code == 404:
        result = {"sha256": sha256, "source": "virustotal", "found": False,
                  "note": "Hash not seen by VirusTotal. Unknown, not necessarily safe."}
    elif resp.status_code == 429:
        return {"sha256": sha256, "error": "VirusTotal rate limit reached (4/min on free tier); verdict unknown"}
    else:
        resp.raise_for_status()
        attrs = resp.json()["data"]["attributes"]
        stats = attrs.get("last_analysis_stats", {})
        result = {"sha256": sha256, "source": "virustotal", **_hash_summary({
            "found": True, **stats,
            "family": (attrs.get("popular_threat_classification") or {}).get("suggested_threat_label"),
            "type": attrs.get("type_description"), "name": attrs.get("meaningful_name"),
        })}
    _cache_put("hash", sha256, result)
    return result


def _hash_summary(d: dict) -> dict:
    mal = d.get("malicious", 0) or 0
    total = sum((d.get(k) or 0) for k in ("malicious", "suspicious", "harmless", "undetected"))
    out = dict(d)
    if d.get("found", True):
        out["detection_ratio"] = f"{mal}/{total}" if total else "0/0"
        out["verdict"] = "malicious" if mal >= 5 else "suspicious" if mal > 0 else "clean"
    return out
