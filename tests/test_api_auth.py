from fastapi.testclient import TestClient

from aegis_core.config import get_settings
from api.app import create_app
from tests.conftest import API_KEY_HEADERS, TEST_API_KEY


def test_public_routes_do_not_require_api_key():
    client = TestClient(create_app())
    assert client.get("/health").status_code == 200
    assert client.get("/").status_code == 200
    assert client.get("/static/app.js").status_code == 200


def test_api_routes_reject_missing_and_wrong_key():
    client = TestClient(create_app())
    missing = client.get("/api/telemetry/events")
    assert missing.status_code == 401
    assert missing.json()["detail"] == "Invalid or missing X-API-Key"

    wrong = client.get("/api/telemetry/events", headers={"X-API-Key": "not-the-key"})
    assert wrong.status_code == 401

    ok = client.get("/api/telemetry/events", headers=API_KEY_HEADERS)
    assert ok.status_code == 200


def test_api_key_reads_aegis_api_key_env(monkeypatch):
    monkeypatch.setenv("AEGIS_API_KEY", "rotated-secret-key")
    get_settings.cache_clear()
    client = TestClient(create_app())
    denied = client.post("/api/pipeline/tick", headers={"X-API-Key": TEST_API_KEY})
    assert denied.status_code == 401
    allowed = client.post("/api/pipeline/tick", headers={"X-API-Key": "rotated-secret-key"})
    assert allowed.status_code == 200


def test_legacy_unprefixed_routes_are_not_exposed():
    client = TestClient(create_app())
    assert client.post("/telemetry/ingest", headers=API_KEY_HEADERS).status_code == 404
    assert client.get("/pipeline/stats").status_code == 404


def test_unconfigured_api_key_fails_closed(monkeypatch):
    monkeypatch.setenv("AEGIS_API_KEY", "   ")
    get_settings.cache_clear()
    client = TestClient(create_app())
    response = client.get("/api/pipeline/stats", headers={"X-API-Key": "anything"})
    assert response.status_code == 503
    assert "AEGIS_API_KEY" in response.json()["detail"]
