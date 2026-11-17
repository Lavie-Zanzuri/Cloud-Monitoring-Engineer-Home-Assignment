"""Web app tests against a throwaway SQLite database."""
import os
import tempfile

_db_file = os.path.join(tempfile.mkdtemp(), "test.db")
os.environ["DATABASE_URL"] = f"sqlite:///{_db_file}"
os.environ["INSTANCE_ID"] = "test-instance"

import pytest  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

import web.main as main  # noqa: E402

PHISH = open("samples/phishing_paypal.eml").read()
LEGIT = open("samples/legit_github.eml").read()


@pytest.fixture(scope="module")
def client():
    with TestClient(main.app) as c:      # "with" runs the startup (creates tables)
        yield c


def test_health_is_up_and_names_the_instance(client):
    r = client.get("/health")
    assert r.status_code == 200
    assert r.json()["instance"] == "test-instance"
    assert r.headers["X-Served-By"] == "test-instance"


def test_ready_checks_the_database(client):
    assert client.get("/health/ready").json()["database"] == "ok"


def test_ready_reports_503_when_db_is_down(client, monkeypatch):
    monkeypatch.setattr(main, "db_is_reachable", lambda: False)
    r = client.get("/health/ready")
    assert r.status_code == 503 and r.json()["database"] == "unreachable"
    assert client.get("/health").status_code == 200        # liveness unaffected


def test_scan_phishing_text(client):
    r = client.post("/api/scan", json={"content": PHISH})
    assert r.status_code == 200
    body = r.json()
    assert body["verdict"] == "Phishing" and body["score"] == 100
    assert body["scan_id"] > 0 and body["findings"]


def test_scan_legit_file_upload(client):
    r = client.post("/api/scan/file", files={"file": ("mail.eml", LEGIT.encode(), "message/rfc822")})
    assert r.status_code == 200 and r.json()["verdict"] == "Safe"


def test_history_feeds_back_into_detection(client):
    client.post("/api/scan", json={"content": PHISH})
    titles = [f["title"] for f in client.post("/api/scan", json={"content": PHISH}).json()["findings"]]
    assert "Sender previously flagged" in titles


def test_history_lists_newest_first_without_email_content(client):
    scans = client.get("/api/history?limit=5").json()["scans"]
    assert scans and scans[0]["id"] > scans[-1]["id"]
    assert set(scans[0]) == {"id", "created_at", "sender", "subject", "verdict", "score",
                             "indicators", "served_by"}


@pytest.mark.parametrize("payload", [{"content": ""}, {}, {"content": 123}])
def test_bad_json_is_rejected(client, payload):
    assert client.post("/api/scan", json=payload).status_code == 422


def test_empty_file_is_rejected(client):
    assert client.post("/api/scan/file", files={"file": ("a.eml", b"  ", "text/plain")}).status_code == 400


def test_oversized_file_is_rejected(client, monkeypatch):
    monkeypatch.setattr(main, "MAX_EMAIL_BYTES", 100)
    r = client.post("/api/scan/file", files={"file": ("a.eml", b"x" * 500, "text/plain")})
    assert r.status_code == 413


def test_ui_is_served(client):
    r = client.get("/")
    assert r.status_code == 200 and "Phishing Detector" in r.text


def test_times_are_returned_with_timezone(client):
    # SQLite forgets the timezone; the API must still say the time is UTC,
    # otherwise the browser shows it shifted by the user's UTC offset.
    created = client.get("/api/history?limit=1").json()["scans"][0]["created_at"]
    assert created.endswith("+00:00")