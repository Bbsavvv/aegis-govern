import aegis_core.config as config


def test_listen_port_uses_railway_port(monkeypatch):
    monkeypatch.setenv("PORT", "4321")
    monkeypatch.delenv("AEGIS_PORT", raising=False)
    assert config.listen_port() == 4321


def test_listen_host_is_public_when_port_is_set(monkeypatch):
    monkeypatch.delenv("HOST", raising=False)
    monkeypatch.delenv("AEGIS_HOST", raising=False)
    monkeypatch.setenv("PORT", "8080")
    assert config.listen_host() == "0.0.0.0"


def test_listen_host_defaults_loopback_without_paas_port(monkeypatch):
    monkeypatch.delenv("HOST", raising=False)
    monkeypatch.delenv("AEGIS_HOST", raising=False)
    monkeypatch.delenv("PORT", raising=False)
    monkeypatch.delenv("RAILWAY_ENVIRONMENT", raising=False)
    monkeypatch.delenv("AEGIS_PORT", raising=False)
    assert config.listen_host() == "127.0.0.1"
