import io
import time

import pytest

from securex.web import create_app

BASE = "http://127.0.0.1:8721"
PASS = "correct horse battery staple"


@pytest.fixture
def app(tmp_path):
    app = create_app(tmp_path / "web.sxvault", "launch-test-token")
    app.config["TESTING"] = True
    yield app
    app.extensions["securex"]["stop"].set()
    app.extensions["securex"]["vault"].lock()


@pytest.fixture
def client(app):
    client = app.test_client()
    result = client.post(
        "/api/session", base_url=BASE, headers={"Origin": BASE}, json={"token": "launch-test-token"}
    )
    assert result.status_code == 200
    assert "HttpOnly" in result.headers["Set-Cookie"]
    assert "SameSite=Strict" in result.headers["Set-Cookie"]
    return client


def post(client, path, body=None):
    return client.post("/api/" + path, base_url=BASE, headers={"Origin": BASE}, json=body or {})


def test_launch_auth_and_host_boundary(app):
    client = app.test_client()
    assert client.get("/api/status", base_url=BASE).status_code == 401
    assert client.get("/", base_url="http://evil.example:8721").status_code == 403
    assert post(client, "session", {"token": "wrong"}).status_code == 401
    assert post(client, "session", {"token": "é"}).status_code == 401


def test_origin_and_missing_origin_rejected(client):
    for headers in [{}, {"Origin": "https://evil.example"}]:
        assert (
            client.post(
                "/api/create", base_url=BASE, headers=headers, json={"passphrase": PASS}
            ).status_code
            == 403
        )


def test_workflow(client):
    assert post(client, "create", {"passphrase": PASS}).status_code == 200
    result = client.post(
        "/api/files",
        base_url=BASE,
        headers={"Origin": BASE},
        data={"file": (io.BytesIO(b"a private document"), "notes.txt")},
    )
    assert result.status_code == 201
    item = result.json["file"]
    assert "key" not in item
    result = client.get("/api/files/" + item["id"], base_url=BASE)
    assert result.data == b"a private document"
    assert "attachment" in result.headers["Content-Disposition"]
    assert post(client, "verify").json["ok"]
    assert client.get("/api/backup", base_url=BASE).data[:2] == b"PK"
    assert post(client, "lock").status_code == 200
    assert client.get("/api/files", base_url=BASE).status_code == 423
    assert post(client, "unlock", {"passphrase": PASS}).status_code == 200
    assert (
        client.delete(
            "/api/files/" + item["id"], base_url=BASE, headers={"Origin": BASE}
        ).status_code
        == 200
    )
    assert client.get("/api/files", base_url=BASE).json["files"] == []


def test_idle_lock_does_not_require_a_request(app, client):
    post(client, "create", {"passphrase": PASS})
    app.extensions["securex"]["state"]["last"] -= 301
    deadline = time.monotonic() + 3
    while app.extensions["securex"]["vault"].unlocked and time.monotonic() < deadline:
        time.sleep(0.02)
    assert not app.extensions["securex"]["vault"].unlocked


def test_poll_does_not_reset_activity(app, client):
    post(client, "create", {"passphrase": PASS})
    before = app.extensions["securex"]["state"]["last"]
    assert client.get("/api/status", base_url=BASE).json["unlocked"]
    assert before == app.extensions["securex"]["state"]["last"]


def test_rate_limit(client):
    post(client, "create", {"passphrase": PASS})
    post(client, "lock")
    assert post(client, "unlock", {"passphrase": "wrong"}).status_code == 400
    assert post(client, "unlock", {"passphrase": "wrong"}).status_code == 429


def test_security_headers_and_static_assets(client):
    result = client.get("/", base_url=BASE)
    assert result.status_code == 200
    assert result.headers["Cache-Control"] == "no-store"
    assert result.headers["X-Frame-Options"] == "DENY"
    assert "default-src 'self'" in result.headers["Content-Security-Policy"]
    for asset in ("app.js", "style.css", "icon.svg"):
        assert client.get("/static/" + asset, base_url=BASE).status_code == 200


def test_bad_json_returns_400(client):
    assert (
        client.post(
            "/api/create", base_url=BASE, headers={"Origin": BASE}, json=["not", "an object"]
        ).status_code
        == 400
    )


def test_no_plaintext_spooling(app):
    with app.test_request_context():
        request = app.request_class.from_values()
        assert isinstance(request._get_file_stream(), io.BytesIO)


def test_events_never_include_filenames(client):
    post(client, "create", {"passphrase": PASS})
    client.post(
        "/api/files",
        base_url=BASE,
        headers={"Origin": BASE},
        data={"file": (io.BytesIO(b"x"), "top-secret.txt")},
    )
    result = client.get("/api/events", base_url=BASE)
    assert "top-secret" not in result.text and PASS not in result.text
