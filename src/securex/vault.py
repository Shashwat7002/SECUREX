"""Versioned envelope encryption. See docs/SECURITY_MODEL.md before changing this format."""

import base64
import hashlib
import json
import os
import re
import secrets
import tempfile
import zipfile
from datetime import UTC, datetime
from pathlib import Path

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from filelock import FileLock

MAX_FILE_SIZE = 64 * 1024 * 1024
MAX_FILES = 10000
PREFIX = b"SECUREX/1/"


class VaultError(Exception):
    """An expected failure safe to show to the user."""


def encode(value):
    return base64.b64encode(value).decode("ascii")


def decode(value):
    return base64.b64decode(value, validate=True)


def seal(key, data, context):
    nonce = secrets.token_bytes(12)
    return nonce + AESGCM(key).encrypt(nonce, data, PREFIX + context)


def unseal(key, data, context):
    try:
        return AESGCM(key).decrypt(data[:12], data[12:], PREFIX + context)
    except (InvalidTag, ValueError) as exc:
        raise VaultError("Authentication failed: wrong passphrase or damaged vault data.") from exc


def derive(passphrase, salt):
    if not isinstance(passphrase, str) or len(passphrase) > 1024:
        raise VaultError("Passphrase must contain at most 1,024 characters.")
    return Scrypt(salt=salt, length=32, n=2**17, r=8, p=1).derive(passphrase.encode("utf-8"))


def check_passphrase(value):
    if not isinstance(value, str) or not 12 <= len(value) <= 1024:
        raise VaultError("Use a passphrase between 12 and 1,024 characters.")


def atomic_write(path, data):
    """Commit one file with private permissions; never expose partially written ciphertext."""
    fd, name = tempfile.mkstemp(prefix=".pending-", dir=path.parent)
    try:
        with os.fdopen(fd, "wb") as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(name, path)
        if os.name == "posix":
            dir_fd = os.open(path.parent, os.O_RDONLY)
            try:
                os.fsync(dir_fd)
            finally:
                os.close(dir_fd)
    finally:
        if os.path.exists(name):
            os.unlink(name)


def json_bytes(value):
    return json.dumps(value, ensure_ascii=False, separators=(",", ":")).encode("utf-8")


class Vault:
    def __init__(self, path):
        self.path = Path(path).expanduser().resolve()
        self.path.mkdir(parents=True, exist_ok=True, mode=0o700)
        self._lock = FileLock(str(self.path / ".lock"), timeout=10, mode=0o600)
        self._key = None
        self._id = None

    @property
    def initialized(self):
        return (self.path / "key.json").is_file()

    @property
    def unlocked(self):
        return self._key is not None and self.initialized

    def create(self, passphrase):
        check_passphrase(passphrase)
        with self._lock:
            if any(p.name != ".lock" for p in self.path.iterdir()):
                raise VaultError(
                    "Choose an empty directory. Existing vault data will not be replaced."
                )
            self._key = secrets.token_bytes(32)
            self._id = secrets.token_hex(16)
            (self.path / "objects").mkdir(mode=0o700)
            # Publish the key last. Interrupted creation cannot be mistaken for a valid vault.
            self._save({"files": [], "created": datetime.now(UTC).isoformat()})
            self._write_key(passphrase)

    def _header(self):
        try:
            header = json.loads((self.path / "key.json").read_bytes())
            if header["version"] != 1 or not re.fullmatch(r"[0-9a-f]{32}", header["id"]):
                raise ValueError()
            if len(decode(header["salt"])) != 16 or len(decode(header["wrapped"])) != 60:
                raise ValueError()
            return header
        except (OSError, ValueError, KeyError, TypeError) as exc:
            raise VaultError(
                "Vault key is missing, damaged, or uses an unsupported format."
            ) from exc

    def unlock(self, passphrase):
        with self._lock:
            self.lock()
            header = self._header()
            try:
                key = unseal(
                    derive(passphrase, decode(header["salt"])),
                    decode(header["wrapped"]),
                    b"master/" + header["id"].encode(),
                )
                self._key, self._id = key, header["id"]
                self._catalog()
            except Exception:
                self.lock()
                raise

    def lock(self):
        # Python cannot promise memory zeroization. Drop references; document the limitation.
        self._key = self._id = None

    def _write_key(self, passphrase):
        salt = secrets.token_bytes(16)
        wrapped = seal(derive(passphrase, salt), self._key, b"master/" + self._id.encode())
        atomic_write(
            self.path / "key.json",
            json_bytes(
                {
                    "version": 1,
                    "id": self._id,
                    "salt": encode(salt),
                    "wrapped": encode(wrapped),
                    "kdf": "scrypt-N131072-r8-p1",
                    "cipher": "AES-256-GCM",
                }
            ),
        )

    def _catalog(self):
        if not self.unlocked:
            self.lock()
            raise VaultError("Vault is locked. Unlock it to continue.")
        try:
            data = (self.path / "catalog.enc").read_bytes()
            catalog = json.loads(unseal(self._key, data, b"catalog/" + self._id.encode()))
            if not isinstance(catalog["files"], list) or len(catalog["files"]) > MAX_FILES:
                raise ValueError()
            for item in catalog["files"]:
                if not re.fullmatch(r"[0-9a-f]{32}", item["id"]):
                    raise ValueError()
            return catalog
        except (OSError, ValueError, KeyError, TypeError) as exc:
            raise VaultError("The encrypted catalog is damaged or missing.") from exc

    def _save(self, catalog):
        atomic_write(
            self.path / "catalog.enc",
            seal(self._key, json_bytes(catalog), b"catalog/" + self._id.encode()),
        )

    def list_files(self):
        with self._lock:
            return [
                {k: v for k, v in item.items() if k != "key"} for item in self._catalog()["files"]
            ]

    def add(self, name, data):
        name = str(name).replace("\\", "/").split("/")[-1]
        if not name or name in (".", "..") or len(name) > 240 or any(ord(c) < 32 for c in name):
            raise VaultError("Choose a filename of 1–240 characters without control characters.")
        if len(data) > MAX_FILE_SIZE:
            raise VaultError("Each file must be 64 MiB or smaller.")
        with self._lock:
            catalog = self._catalog()
            if len(catalog["files"]) >= MAX_FILES:
                raise VaultError("This vault has reached its 10,000-file limit.")
            identity, key = secrets.token_hex(16), secrets.token_bytes(32)
            entry = {
                "id": identity,
                "name": name,
                "size": len(data),
                "key": encode(key),
                "added": datetime.now(UTC).isoformat(),
                "sha256": hashlib.sha256(data).hexdigest(),
            }
            target = self.path / "objects" / (identity + ".enc")
            atomic_write(
                target, seal(key, data, b"file/" + self._id.encode() + b"/" + identity.encode())
            )
            catalog["files"].append(entry)
            # A failed catalog commit leaves orphan ciphertext, never a false success.
            self._save(catalog)
            return {k: v for k, v in entry.items() if k != "key"}

    def _read(self, item):
        try:
            path = self.path / "objects" / (item["id"] + ".enc")
            if path.stat().st_size > MAX_FILE_SIZE + 28:
                raise VaultError("Encrypted object exceeds the supported file size.")
            data = unseal(
                decode(item["key"]),
                path.read_bytes(),
                b"file/" + self._id.encode() + b"/" + item["id"].encode(),
            )
            if len(data) != item["size"] or hashlib.sha256(data).hexdigest() != item["sha256"]:
                raise VaultError("File checksum does not match the authenticated catalog.")
            return data
        except OSError as exc:
            raise VaultError("Encrypted file is missing or cannot be read.") from exc

    def get(self, identity):
        with self._lock:
            for item in self._catalog()["files"]:
                if item["id"] == identity:
                    return item["name"], self._read(item)
            raise VaultError("File not found in this vault.")

    def remove(self, identity):
        with self._lock:
            catalog = self._catalog()
            remaining = [item for item in catalog["files"] if item["id"] != identity]
            if len(remaining) == len(catalog["files"]):
                raise VaultError("File not found in this vault.")
            catalog["files"] = remaining
            self._save(
                catalog
            )  # Remove the live key reference before deleting the encrypted object.
            (self.path / "objects" / (identity + ".enc")).unlink(missing_ok=True)

    def verify(self):
        with self._lock:
            catalog = self._catalog()
            results = []
            for item in catalog["files"]:
                try:
                    self._read(item)
                    results.append({"id": item["id"], "name": item["name"], "ok": True})
                except VaultError as exc:
                    results.append(
                        {"id": item["id"], "name": item["name"], "ok": False, "error": str(exc)}
                    )
            known = {item["id"] + ".enc" for item in catalog["files"]}
            orphans = len(set(p.name for p in (self.path / "objects").glob("*.enc")) - known)
            return {"ok": all(item["ok"] for item in results), "files": results, "orphans": orphans}

    def change_passphrase(self, current, replacement):
        check_passphrase(replacement)
        with self._lock:
            self.unlock(current)
            self._write_key(replacement)

    def backup(self, destination):
        """Write an encrypted, consistent snapshot to a file-like object."""
        with self._lock:
            catalog = self._catalog()
            with zipfile.ZipFile(destination, "w", compression=zipfile.ZIP_STORED) as archive:
                archive.writestr("objects/", b"")
                for name in ["key.json", "catalog.enc"]:
                    archive.write(self.path / name, name)
                for item in catalog["files"]:
                    name = "objects/" + item["id"] + ".enc"
                    archive.write(self.path / name, name)

    def destroy(self, passphrase, confirmation):
        if confirmation != "DESTROY":
            raise VaultError("Type DESTROY exactly to remove the vault key.")
        with self._lock:
            self.unlock(passphrase)
            (self.path / "key.json").unlink()
            self.lock()
