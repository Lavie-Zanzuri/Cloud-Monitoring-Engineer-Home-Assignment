"""Cache behaviour, with a fake in-memory Redis (no server needed)."""
import os
import tempfile

os.environ.setdefault("DATABASE_URL", f"sqlite:///{os.path.join(tempfile.mkdtemp(), 'test.db')}")
os.environ.setdefault("INSTANCE_ID", "test-instance")

import pytest  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

import web.cache as cache  # noqa: E402
import web.main as main  # noqa: E402
from detector.analyzer import AnalysisResult, analyze  # noqa: E402

PHISH = open("samples/phishing_paypal.eml").read()


class FakeRedis:
    def __init__(self):
        self.data, self.ttls = {}, {}

    def get(self, key):
        return self.data.get(key)

    def set(self, key, value, ex=None):
        self.data[key], self.ttls[key] = value, ex

    def ping(self):
        return True


class BrokenRedis:
    """Simulates ElastiCache being down: every call fails."""
    def get(self, key):
        raise ConnectionError("cache down")

    set = ping = get


@pytest.fixture
def client():
    with TestClient(main.app) as c:
        yield c


@pytest.fixture
def fake_cache(monkeypatch):
    fake = FakeRedis()
    monkeypatch.setattr(cache, "CACHE_URL", "redis://fake:6379/0")
    monkeypatch.setattr(cache, "_client", fake)
    return fake


def test_result_survives_a_round_trip_through_the_cache():
    original = analyze(PHISH)
    rebuilt = AnalysisResult.from_dict(original.to_dict())
    assert rebuilt == original


def test_second_identical_scan_is_served_from_cache(client, fake_cache):
    first = client.post("/api/scan", json={"content": PHISH}).json()
    second = client.post("/api/scan", json={"content": PHISH}).json()
    assert first["cached"] is False and second["cached"] is True
    assert second["verdict"] == first["verdict"]
    (key,) = fake_cache.data
    assert key.startswith("analysis:v1:") and fake_cache.ttls[key] == cache.CACHE_TTL_SECONDS


def test_cache_down_means_scans_still_work(client, monkeypatch):
    monkeypatch.setattr(cache, "CACHE_URL", "redis://broken:6379/0")
    monkeypatch.setattr(cache, "_client", BrokenRedis())
    r = client.post("/api/scan", json={"content": PHISH})
    assert r.status_code == 200 and r.json()["cached"] is False
    ready = client.get("/health/ready")
    assert ready.status_code == 200                      # cache is not a readiness dependency
    assert ready.json()["cache"] == "unreachable"


def test_no_cache_configured_is_reported_as_disabled(client):
    assert client.get("/health/ready").json()["cache"] == "disabled"
