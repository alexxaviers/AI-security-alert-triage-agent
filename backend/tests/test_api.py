import json

from fastapi.testclient import TestClient

from app.config import DATA_DIR
from app.main import app

client = TestClient(app)
ALERTS = json.loads((DATA_DIR / "alerts.json").read_text())


def _post(alert, **params):
    r = client.post("/alerts", json=alert, params={"sync": "true", **params})
    assert r.status_code == 201, r.text
    return r.json()


def test_health():
    assert client.get("/health").json()["status"] == "ok"


def test_create_triage_and_get():
    a = next(x for x in ALERTS if x["rule_name"] == "Ransomware Behavior")
    body = _post(a)
    assert body["status"] in ("triaged", "needs_review")
    assert body["verdict"]["severity"] == "critical"
    assert body["verdict"]["technique"] == "T1486"
    got = client.get(f"/alerts/{a['id']}").json()
    assert got["raw"]["description"] == a["description"]


def test_tool_calls_are_audited():
    a = next(x for x in ALERTS if x.get("file_hash"))
    body = _post(a)
    assert any(c["tool"] == "check_file_hash" for c in body["tool_calls"])


def test_duplicate_id_conflicts():
    a = ALERTS[10]
    _post(a)
    assert client.post("/alerts", json=a).status_code == 409


def test_generated_id_and_minimal_alert():
    body = _post({"title": "50 failed logins for admin", "rule_name": "Brute Force Login Attempt",
                  "src_ip": "10.1.1.1"})
    assert body["id"].startswith("ALR-")
    assert body["verdict"]["technique"] == "T1110.001"


def test_list_filter_and_sort():
    for a in ALERTS[20:30]:
        _post(a)
    r = client.get("/alerts", params={"sort": "severity", "limit": 100}).json()
    ranks = {"critical": 4, "high": 3, "medium": 2, "low": 1, None: 0}
    sevs = [ranks[i["severity"]] for i in r["items"]]
    assert sevs == sorted(sevs, reverse=True)
    crit = client.get("/alerts", params={"severity": "critical"}).json()
    assert all(i["severity"] == "critical" for i in crit["items"])


def test_override_and_export():
    a = ALERTS[40]
    _post(a)
    r = client.post(f"/alerts/{a['id']}/override",
                    json={"severity": "critical", "technique": "t1078", "note": "Confirmed takeover", "analyst": "xa"})
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["status"] == "overridden" and body["overrides"][-1]["technique"] == "T1078"
    listed = client.get("/alerts", params={"q": a["id"]}).json()["items"][0]
    assert listed["severity"] == "critical" and listed["overridden"]
    export = client.get("/overrides/export").json()
    assert export[a["id"]]["severity"] == "critical"


def test_override_rejects_bad_technique():
    a = ALERTS[41]
    _post(a)
    r = client.post(f"/alerts/{a['id']}/override", json={"severity": "low", "technique": "T0000"})
    assert r.status_code == 422


def test_stats():
    s = client.get("/stats").json()
    assert s["total"] > 0 and s["engine"] == "baseline-rules"
    assert sum(s["by_severity"].values()) <= s["total"]


def test_missing_alert_404():
    assert client.get("/alerts/NOPE").status_code == 404


def test_request_session_is_released_before_background_triage(monkeypatch):
    # A background triage takes seconds; if the request's session still holds a pooled connection
    # while it runs, a burst of alerts exhausts the pool.
    from app import main
    from app.db import engine

    checked_out = []
    monkeypatch.setattr(main, "triage_alert", lambda alert_id: checked_out.append(engine.pool.checkedout()))
    a = client.post("/alerts", json={"title": "pool check"}).json()
    client.post(f"/alerts/{a['id']}/retriage")
    assert checked_out == [0, 0]
