import json

from securex.cli import main


def test_cli_round_trip(tmp_path, monkeypatch, capsys):
    monkeypatch.setattr(
        "securex.cli.password", lambda confirm=False: "correct horse battery staple"
    )
    vault = str(tmp_path / "cli.sxvault")
    assert main(["--vault", vault, "init"]) == 0
    original = tmp_path / "original.txt"
    original.write_bytes(b"CLI round trip")
    assert main(["--vault", vault, "add", str(original)]) == 0
    capsys.readouterr()
    assert main(["--vault", vault, "list"]) == 0
    identity = json.loads(capsys.readouterr().out)[0]["id"]
    target = tmp_path / "exported.txt"
    assert main(["--vault", vault, "export", identity, str(target)]) == 0
    assert target.read_bytes() == original.read_bytes()
    assert main(["--vault", vault, "export", identity, str(target)]) == 1
    assert main(["--vault", vault, "verify"]) == 0
    assert main(["--vault", vault, "backup", str(tmp_path / "backup.zip")]) == 0
    assert main(["--vault", vault, "remove", identity]) == 0
