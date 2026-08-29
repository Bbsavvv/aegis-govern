from fastapi.testclient import TestClient

from api.app import create_app
from tests.factories import transfer_event


def test_health_and_full_enforcement_loop():
    client = TestClient(create_app())
    health = client.get("/health")
    assert health.status_code == 200
    assert health.json()["status"] == "ok"

    ingested = client.post("/telemetry/ingest", json=transfer_event().model_dump(mode="json"))
    assert ingested.status_code == 200
    event_id = ingested.json()["event"]["event_id"]

    crosswalk = client.post("/evaluations/crosswalk", params={"event_id": event_id})
    assert crosswalk.status_code == 200
    assert crosswalk.json()["count"] >= 1

    generated = client.post("/remediations/generate")
    assert generated.status_code == 200
    assert generated.json()["count"] >= 1

    listed = client.get("/remediations/pull-requests")
    assert listed.json()["count"] >= 1
    pr = listed.json()["pull_requests"][0]
    assert pr["files"]
    assert pr["labels"]


def test_pipeline_tick_returns_ids():
    client = TestClient(create_app())
    response = client.post("/pipeline/tick", params={"batch_size": 5})
    assert response.status_code == 200
    body = response.json()
    assert len(body["ingested_events"]) == 5
    assert "store" in body


def test_dashboard_and_proof_verify_unlock():
    client = TestClient(create_app())
    home = client.get("/")
    assert home.status_code == 200
    assert b"Aegis Control Plane" in home.content
    css = client.get("/static/styles.css")
    assert css.status_code == 200
    js = client.get("/static/app.js")
    assert js.status_code == 200

    audit = client.post(
        "/acquisition/audit",
        json={"target": "https://api.acme.test/v1", "annual_turnover_eur": 1_000_000, "sweep_size": 3},
    )
    assert audit.status_code == 200
    report_id = audit.json()["report_id"]
    assert report_id.startswith("prf_")
    verify = client.get(f"/acquisition/reports/{report_id}/verify")
    assert verify.status_code == 200
    assert verify.json()["valid"] is True
    assert verify.json()["checks"]["hmac_signature"] is True

    packaged = client.post(f"/acquisition/package/{report_id}")
    assert packaged.status_code == 200
    package_id = packaged.json()["package_id"]
    license_key = packaged.json()["license_key"]
    unlocked = client.post(
        f"/acquisition/packages/{package_id}/unlock",
        json={"license_key": license_key},
    )
    assert unlocked.status_code == 200
    assert unlocked.json()["unlocked"] is True
    assert unlocked.json()["files"]
    client = TestClient(create_app())
    audit = client.post(
        "/acquisition/audit",
        json={"target": "https://api.northstar.example/v1/chat", "annual_turnover_eur": 250000000, "sweep_size": 3},
    )
    assert audit.status_code == 200
    report_id = audit.json()["report_id"]
    assert audit.json()["integrity"]["signature"]
    packaged = client.post(f"/acquisition/package/{report_id}")
    assert packaged.status_code == 200
    body = packaged.json()
    assert body["executive_summary"]
    unlock = client.post(
        "/acquisition/unlock",
        json={"license_key": body["license_key"], "sealed_patch": body["sealed_patch"]},
    )
    assert unlock.status_code == 200
    assert unlock.json()["unlocked"] is True
    denied = client.post(
        "/acquisition/unlock",
        json={"license_key": "AEGIS-ENT-nope", "sealed_patch": body["sealed_patch"]},
    )
    assert denied.status_code == 403
