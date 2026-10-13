import io
import json
import os
import zipfile
from concurrent.futures import ThreadPoolExecutor

import pytest

from securex.vault import Vault, VaultError

PASS = "correct horse battery staple"


@pytest.fixture
def vault(tmp_path):
    instance = Vault(tmp_path / "test.sxvault")
    instance.create(PASS)
    yield instance
    instance.lock()


@pytest.mark.parametrize(
    "name,data",
    [("empty.txt", b""), ("研究.pdf", b"private report"), ("binary.dat", bytes(range(256)) * 5000)],
)
def test_round_trip_and_restart(vault, name, data):
    item = vault.add(name, data)
    assert "key" not in item
    assert vault.get(item["id"]) == (name, data)
    vault.lock()
    with pytest.raises(VaultError, match="locked"):
        vault.get(item["id"])
    reopened = Vault(vault.path)
    reopened.unlock(PASS)
    assert reopened.get(item["id"]) == (name, data)
    assert reopened.verify()["ok"]


def test_metadata_and_content_not_stored_plaintext(vault):
    vault.add("confidential-unique-name.txt", b"highly sensitive payload")
    for path in vault.path.rglob("*"):
        if path.is_file():
            data = path.read_bytes()
            assert b"confidential-unique-name" not in data
            assert b"highly sensitive payload" not in data
            assert PASS.encode() not in data


def test_wrong_password_locks(vault):
    with pytest.raises(VaultError, match="Authentication"):
        vault.unlock("incorrect password")
    assert not vault.unlocked


def test_tampered_blob_fails_before_export(vault):
    item = vault.add("a.txt", b"secret")
    path = vault.path / "objects" / (item["id"] + ".enc")
    raw = bytearray(path.read_bytes())
    raw[-1] ^= 1
    path.write_bytes(raw)
    with pytest.raises(VaultError, match="Authentication"):
        vault.get(item["id"])
    assert not vault.verify()["ok"]


def test_tampered_catalog_fails_unlock(vault):
    path = vault.path / "catalog.enc"
    raw = bytearray(path.read_bytes())
    raw[-1] ^= 1
    path.write_bytes(raw)
    with pytest.raises(VaultError):
        vault.unlock(PASS)
    assert not vault.unlocked


def test_objects_cannot_be_swapped(vault):
    first = vault.add("a", b"same")
    second = vault.add("b", b"same")
    path = vault.path / "objects"
    (path / (first["id"] + ".enc")).write_bytes((path / (second["id"] + ".enc")).read_bytes())
    assert not vault.verify()["ok"]


def test_rotation_preserves_data(vault):
    item = vault.add("a", b"secret")
    before = (vault.path / "objects" / (item["id"] + ".enc")).read_bytes()
    vault.change_passphrase(PASS, "a much better passphrase")
    with pytest.raises(VaultError):
        vault.unlock(PASS)
    vault.unlock("a much better passphrase")
    assert vault.get(item["id"])[1] == b"secret"
    assert (vault.path / "objects" / (item["id"] + ".enc")).read_bytes() == before


def test_remove_and_backup_restore(vault, tmp_path):
    item = vault.add("a.txt", b"recovery")
    backup = io.BytesIO()
    vault.backup(backup)
    vault.remove(item["id"])
    assert not vault.list_files()
    with pytest.raises(VaultError, match="not found"):
        vault.get(item["id"])
    backup.seek(0)
    restored = tmp_path / "restored"
    with zipfile.ZipFile(backup) as archive:
        assert len(archive.namelist()) == 4
        archive.extractall(restored)  # Only the archive just produced by this test.
    recovered = Vault(restored)
    recovered.unlock(PASS)
    assert recovered.get(item["id"])[1] == b"recovery"


def test_destroy_requires_confirmation_and_passphrase(vault):
    vault.add("a", b"a")
    with pytest.raises(VaultError):
        vault.destroy(PASS, "destroy")
    assert vault.initialized
    with pytest.raises(VaultError):
        vault.destroy("wrong", "DESTROY")
    assert vault.initialized
    vault.destroy(PASS, "DESTROY")
    assert not vault.initialized and not vault.unlocked
    assert (vault.path / "catalog.enc").exists()
    with pytest.raises(VaultError):
        vault.unlock(PASS)
    with pytest.raises(VaultError, match="empty directory"):
        vault.create(PASS)


def test_concurrent_instances_do_not_lose_updates(vault):
    other = Vault(vault.path)
    other.unlock(PASS)
    with ThreadPoolExecutor(max_workers=2) as pool:
        futures = [
            pool.submit(v.add, f"file-{i}", b"data") for i, v in enumerate([vault, other] * 5)
        ]
        for future in futures:
            future.result()
    assert len(vault.list_files()) == 10
    assert vault.verify()["ok"]


def test_invalid_paths_and_duplicates(vault):
    item = vault.add("../../hello.txt", b"one")
    second = vault.add("hello.txt", b"two")
    assert item["name"] == "hello.txt"
    assert item["id"] != second["id"]
    for name in ("..", "", "a\n.txt", "a" * 241):
        with pytest.raises(VaultError):
            vault.add(name, b"bad")
    with pytest.raises(VaultError, match="not found"):
        vault.get("../../key.json")


def test_size_limit(vault, monkeypatch):
    monkeypatch.setattr("securex.vault.MAX_FILE_SIZE", 4)
    with pytest.raises(VaultError, match="64 MiB"):
        vault.add("large", b"12345")
    assert not vault.list_files()


def test_missing_file_and_orphans(vault):
    item = vault.add("missing", b"x")
    (vault.path / "objects" / (item["id"] + ".enc")).unlink()
    (vault.path / "objects" / "orphan.enc").write_bytes(b"irrelevant")
    result = vault.verify()
    assert not result["ok"] and result["orphans"] == 1


def test_invalid_header(vault):
    path = vault.path / "key.json"
    header = json.loads(path.read_text())
    header["version"] = 99
    path.write_text(json.dumps(header))
    with pytest.raises(VaultError, match="unsupported"):
        vault.unlock(PASS)


def test_failed_catalog_commit_keeps_existing_files(vault, monkeypatch):
    first = vault.add("first", b"safe")

    def failure(*args):
        raise OSError("disk full")

    monkeypatch.setattr(vault, "_save", failure)
    with pytest.raises(OSError):
        vault.add("second", b"uncommitted")
    assert vault.get(first["id"])[1] == b"safe"
    assert len(vault.list_files()) == 1
    assert vault.verify()["orphans"] == 1


@pytest.mark.skipif(os.name != "posix", reason="POSIX mode bits")
def test_private_permissions(vault):
    vault.add("file", b"content")
    for path in [
        vault.path,
        vault.path / "objects",
        vault.path / "key.json",
        vault.path / "catalog.enc",
    ]:
        assert path.stat().st_mode & 0o077 == 0


def test_short_passphrase_rejected(tmp_path):
    vault = Vault(tmp_path / "new")
    with pytest.raises(VaultError, match="12"):
        vault.create("short")
    assert not vault.initialized


def test_empty_backup_restores(vault, tmp_path):
    backup = io.BytesIO()
    vault.backup(backup)
    backup.seek(0)
    restored = tmp_path / "empty-restored"
    with zipfile.ZipFile(backup) as archive:
        archive.extractall(restored)
    recovered = Vault(restored)
    recovered.unlock(PASS)
    assert recovered.list_files() == []
    assert recovered.verify()["ok"]
    recovered.add("new.txt", b"restored empty vault works")
