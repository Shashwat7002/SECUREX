"""Loopback-only dashboard with a launch capability, strict origins and server-side locking."""

import io
import secrets
import threading
import time
from datetime import UTC, datetime
from pathlib import Path

from filelock import Timeout
from flask import Flask, jsonify, request, send_file
from werkzeug.exceptions import HTTPException

from .vault import MAX_FILE_SIZE, Vault, VaultError


def create_app(path, launch_token=None, port=8721, idle_seconds=300):
    app = Flask(__name__, static_folder="static", static_url_path="/static")
    app.config["MAX_CONTENT_LENGTH"] = MAX_FILE_SIZE + 16384
    vault = Vault(path)
    launch_token = launch_token or secrets.token_urlsafe(32)
    session_token = secrets.token_urlsafe(32)
    origin = f"http://127.0.0.1:{port}"
    mutex = threading.RLock()
    state = {"last": time.monotonic(), "failures": 0, "retry": 0.0, "events": []}
    stop = threading.Event()

    def event(message):
        state["events"].insert(0, {"message": message, "at": datetime.now(UTC).isoformat()})
        del state["events"][50:]

    def expire():
        if vault.unlocked and time.monotonic() - state["last"] >= idle_seconds:
            vault.lock()
            event("Vault locked after inactivity")

    def reap():
        while not stop.wait(min(1, idle_seconds)):
            with mutex:
                expire()

    threading.Thread(target=reap, daemon=True).start()
    app.extensions["securex"] = {"vault": vault, "stop": stop, "state": state}

    @app.before_request
    def boundary():
        if request.host != f"127.0.0.1:{port}":
            return jsonify(error="Invalid host."), 403
        if request.path.startswith("/api/"):
            if request.method != "GET" and request.headers.get("Origin") != origin:
                return jsonify(error="Cross-origin request refused."), 403
            if request.path != "/api/session" and not secrets.compare_digest(
                request.cookies.get("securex_session", ""), session_token
            ):
                return jsonify(error="Open the launch link from your terminal."), 401

    @app.after_request
    def headers(response):
        response.headers.update(
            {
                "Cache-Control": "no-store",
                "X-Content-Type-Options": "nosniff",
                "X-Frame-Options": "DENY",
                "Referrer-Policy": "no-referrer",
                "Cross-Origin-Resource-Policy": "same-origin",
                "Content-Security-Policy": "default-src 'self'; script-src 'self'; "
                "style-src 'self'; "
                "img-src 'self' data:; connect-src 'self'; "
                "frame-ancestors 'none'; base-uri 'none'; form-action 'self'",
            }
        )
        return response

    @app.errorhandler(VaultError)
    def expected(exc):
        return jsonify(error=str(exc)), 400

    @app.errorhandler(Timeout)
    def busy(exc):
        return jsonify(error="Vault is busy in another process. Try again."), 409

    @app.errorhandler(OSError)
    def storage(exc):
        return jsonify(
            error="Storage operation failed. Check free space and file permissions."
        ), 500

    @app.errorhandler(HTTPException)
    def http_error(exc):
        return jsonify(error=exc.description), exc.code

    @app.get("/")
    def index():
        return app.send_static_file("index.html")

    @app.post("/api/session")
    def session():
        body = request.get_json(silent=True) or {}
        if not isinstance(body, dict):
            raise VaultError("Expected a JSON object.")
        token = body.get("token")
        if not isinstance(token, str) or not secrets.compare_digest(
            token.encode(), launch_token.encode()
        ):
            return jsonify(error="Invalid launch link. Reopen the link from your terminal."), 401
        response = jsonify(ok=True)
        response.set_cookie("securex_session", session_token, httponly=True, samesite="Strict")
        return response

    @app.route("/api/<path:action>", methods=["GET", "POST", "DELETE"])
    def api(action):
        with mutex:
            expire()
            body = request.get_json(silent=True) or {}
            if not isinstance(body, dict):
                raise VaultError("Expected a JSON object.")
            method = request.method
            if action == "status" and method == "GET":
                return jsonify(
                    initialized=vault.initialized,
                    unlocked=vault.unlocked,
                    directory=Path(path).name,
                    idle_seconds=idle_seconds,
                    destroyed=not vault.initialized and (vault.path / "catalog.enc").exists(),
                )
            # Polling status does not count as activity. Actual operations do.
            state["last"] = time.monotonic()
            if action in ("create", "unlock") and method == "POST":
                if time.monotonic() < state["retry"]:
                    return jsonify(
                        error="Too many attempts. Wait a moment before trying again."
                    ), 429
                try:
                    getattr(vault, action)(body.get("passphrase", ""))
                except VaultError:
                    state["failures"] += 1
                    state["retry"] = time.monotonic() + min(30, 2 ** (state["failures"] - 1))
                    raise
                state["failures"] = 0
                event("Vault created" if action == "create" else "Vault unlocked")
                return jsonify(ok=True)
            if action == "lock" and method == "POST":
                vault.lock()
                event("Vault locked manually")
                return jsonify(ok=True)
            if not vault.unlocked:
                return jsonify(error="Vault is locked. Unlock it to continue."), 423
            if action == "files" and method == "GET":
                return jsonify(files=vault.list_files())
            if action == "files" and method == "POST":
                uploaded = request.files.get("file")
                if not uploaded:
                    raise VaultError("Choose a file to import.")
                item = vault.add(uploaded.filename, uploaded.read(MAX_FILE_SIZE + 1))
                event("File encrypted and added")
                return jsonify(file=item), 201
            if action.startswith("files/"):
                identity = action.split("/")[1]
                if method == "GET":
                    name, data = vault.get(identity)
                    event("File decrypted for export")
                    return send_file(
                        io.BytesIO(data),
                        as_attachment=True,
                        download_name=name,
                        mimetype="application/octet-stream",
                        max_age=0,
                    )
                if method == "DELETE":
                    vault.remove(identity)
                    event("File removed from vault")
                    return jsonify(ok=True)
            if action == "verify" and method == "POST":
                result = vault.verify()
                event("Integrity check passed" if result["ok"] else "Integrity check found damage")
                return jsonify(result)
            if action == "events" and method == "GET":
                return jsonify(events=state["events"])
            if action == "passphrase" and method == "POST":
                vault.change_passphrase(body.get("current", ""), body.get("replacement", ""))
                event("Passphrase changed")
                return jsonify(ok=True)
            if action == "backup" and method == "GET":
                # Spool encrypted data only. Plaintext imports never use this temporary file.
                stream = tempfile_encrypted_backup(vault)
                event("Encrypted backup exported")
                response = send_file(
                    stream,
                    as_attachment=True,
                    download_name="securex-backup.zip",
                    mimetype="application/zip",
                )
                response.call_on_close(stream.close)
                return response
            if action == "destroy" and method == "POST":
                vault.destroy(body.get("passphrase", ""), body.get("confirmation", ""))
                event("Vault key removed")
                return jsonify(ok=True)
            return jsonify(error="Unknown operation."), 404

    # Werkzeug's multipart parser normally spools uploads to disk. Keep plaintext in memory.
    class MemoryRequest(app.request_class):
        def _get_file_stream(self, *args, **kwargs):
            return io.BytesIO()

    app.request_class = MemoryRequest
    return app


def tempfile_encrypted_backup(vault):
    import tempfile

    stream = tempfile.TemporaryFile()
    try:
        vault.backup(stream)
        stream.seek(0)
        return stream
    except Exception:
        stream.close()
        raise
