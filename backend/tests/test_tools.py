"""Tool tests. Live API calls are mocked with httpx MockTransport-style patching."""

import json

import httpx
import pytest

from app.config import get_settings
from tools import TOOLS_BY_NAME
from tools.attack_mapper import map_to_attack, technique_index
from tools.intel import _fixtures, file_hash_reputation, ip_reputation


@pytest.fixture
def live_mode(monkeypatch):
    s = get_settings()
    monkeypatch.setattr(s, "intel_mode", "live")
    monkeypatch.setattr(s, "abuseipdb_api_key", "test-key")
    monkeypatch.setattr(s, "virustotal_api_key", "test-key")
    yield s


def _mock_get(monkeypatch, handler):
    calls = []

    def fake_get(url, **kwargs):
        calls.append((url, kwargs))
        status, body = handler(url, kwargs)
        return httpx.Response(status, json=body, request=httpx.Request("GET", url))

    monkeypatch.setattr("tools.intel.httpx.get", fake_get)
    return calls


# ---------------------------------------------------------------- fixtures --- #
def test_fixture_ip_known_bad():
    ip, rec = next((k, v) for k, v in _fixtures()["ips"].items() if v["abuse_confidence_score"] >= 80)
    r = ip_reputation(ip)
    assert r["source"] == "fixture" and r["abuse_confidence_score"] == rec["abuse_confidence_score"]


def test_private_ip_has_no_reputation():
    r = ip_reputation("10.20.3.4")
    assert r["is_private"] is True


def test_invalid_ip():
    assert "error" in ip_reputation("999.1.1.1")


def test_fixture_hash_malicious_and_unknown():
    h = next(k for k, v in _fixtures()["hashes"].items() if v["malicious"] > 10)
    assert file_hash_reputation(h)["verdict"] == "malicious"
    assert file_hash_reputation("a" * 64)["found"] is False


def test_invalid_hash():
    assert "error" in file_hash_reputation("abc123")


# -------------------------------------------------------------------- live --- #
def test_abuseipdb_live_parsing_and_cache(live_mode, monkeypatch):
    calls = _mock_get(monkeypatch, lambda url, kw: (200, {"data": {
        "abuseConfidenceScore": 97, "countryCode": "RU", "isp": "Bad Host", "usageType": "Data Center",
        "totalReports": 1234, "isTor": False, "lastReportedAt": "2026-10-01T00:00:00Z"}}))
    r1 = ip_reputation("45.155.205.200")
    assert r1["abuse_confidence_score"] == 97 and r1["country"] == "RU" and r1["source"] == "abuseipdb"
    assert calls[0][1]["headers"]["Key"] == "test-key"
    r2 = ip_reputation("45.155.205.200")  # served from the Postgres/SQLite cache
    assert r2.get("cached") is True and len(calls) == 1


def test_abuseipdb_rate_limit(live_mode, monkeypatch):
    _mock_get(monkeypatch, lambda url, kw: (429, {}))
    assert "rate limit" in ip_reputation("45.155.205.201")["error"]


def test_virustotal_live_found(live_mode, monkeypatch):
    h = "b" * 64
    _mock_get(monkeypatch, lambda url, kw: (200, {"data": {"attributes": {
        "last_analysis_stats": {"malicious": 55, "suspicious": 1, "harmless": 0, "undetected": 16},
        "popular_threat_classification": {"suggested_threat_label": "trojan.emotet"},
        "type_description": "Win32 EXE", "meaningful_name": "invoice.exe"}}}))
    r = file_hash_reputation(h)
    assert r["verdict"] == "malicious" and r["detection_ratio"] == "55/72" and r["family"] == "trojan.emotet"


def test_virustotal_live_not_found(live_mode, monkeypatch):
    _mock_get(monkeypatch, lambda url, kw: (404, {"error": {"code": "NotFoundError"}}))
    assert file_hash_reputation("c" * 64)["found"] is False


def test_live_mode_skips_api_for_private_ip(live_mode, monkeypatch):
    calls = _mock_get(monkeypatch, lambda url, kw: (500, {}))
    assert ip_reputation("192.168.1.10")["is_private"] and not calls


# ------------------------------------------------------------------ ATT&CK --- #
def test_attack_data_loaded():
    idx = technique_index()
    assert len(idx) > 500 and idx["T1110"]["name"] == "Brute Force"


@pytest.mark.parametrize("query,expected", [
    ("dumping lsass process memory to steal credentials", "T1003.001"),
    ("repeated MFA push notification requests to the user", "T1621"),
    ("uploading data to personal cloud storage", "T1567.002"),
    ("scheduled task created for persistence", "T1053.005"),
])
def test_attack_mapper_top5(query, expected):
    ids = [m["technique_id"] for m in map_to_attack(query)["matches"]]
    assert expected in ids


def test_langchain_tool_wrappers():
    r = TOOLS_BY_NAME["check_ip_reputation"].invoke({"ip": "10.0.0.1"})
    assert r["is_private"]
    out = TOOLS_BY_NAME["map_to_attack"].invoke({"description": "brute force password guessing"})
    assert len(out["matches"]) == 5
    json.dumps(out)  # tool output must be JSON-serializable for the ToolMessage
