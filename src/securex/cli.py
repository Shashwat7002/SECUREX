"""CLI entrypoint: passwords are prompted, never accepted as command-line arguments."""

import argparse
import getpass
import json
import os
import secrets
import sys
import webbrowser
from pathlib import Path

from filelock import Timeout

from .vault import MAX_FILE_SIZE, Vault, VaultError


def password(confirm=False):
    value = getpass.getpass("Passphrase: ")
    if confirm and value != getpass.getpass("Confirm passphrase: "):
        raise VaultError("Passphrases do not match.")
    return value


def parser():
    root = argparse.ArgumentParser(
        prog="securex", description="Your files. Your keys. Your device."
    )
    root.add_argument("--vault", type=Path, default=Path.home() / ".securex" / "personal.sxvault")
    root.add_argument("--version", action="version", version="SECUREX 0.1.0")
    commands = root.add_subparsers(dest="command", required=True)
    for name in ("init", "list", "verify", "passwd", "destroy"):
        commands.add_parser(name)
    add = commands.add_parser("add")
    add.add_argument("files", type=Path, nargs="+")
    export = commands.add_parser("export")
    export.add_argument("id")
    export.add_argument("destination", type=Path)
    remove = commands.add_parser("remove")
    remove.add_argument("id")
    backup = commands.add_parser("backup")
    backup.add_argument("destination", type=Path)
    serve = commands.add_parser("serve")
    serve.add_argument("--port", type=int, default=8721)
    serve.add_argument("--no-browser", action="store_true")
    return root


def main(argv=None):
    args = parser().parse_args(argv)
    vault = None
    try:
        if args.command == "serve":
            if not 1024 <= args.port <= 65535:
                raise VaultError("Choose a port between 1024 and 65535.")
            from waitress import create_server

            from .web import create_app

            token = secrets.token_urlsafe(32)
            url = f"http://127.0.0.1:{args.port}/#token={token}"
            app = create_app(args.vault, token, args.port)
            server = create_server(
                app,
                host="127.0.0.1",
                port=args.port,
                threads=4,
                max_request_body_size=MAX_FILE_SIZE + 16384,
                inbuf_overflow=MAX_FILE_SIZE + 16384,
            )
            print(
                f"SECUREX · local vault\nOpen: {url}\n"
                "Keep this launch link private. Ctrl+C to stop.",
                flush=True,
            )
            if not args.no_browser:
                webbrowser.open(url)
            try:
                server.run()
            finally:
                server.close()
                app.extensions["securex"]["stop"].set()
                app.extensions["securex"]["vault"].lock()
            return 0
        vault = Vault(args.vault)
        if args.command == "init":
            vault.create(password(confirm=True))
            print(f"Created encrypted vault: {vault.path}")
            return 0
        current = password()
        vault.unlock(current)
        if args.command == "list":
            print(json.dumps(vault.list_files(), indent=2, ensure_ascii=False))
        elif args.command == "add":
            for path in args.files:
                if not path.is_file() or path.stat().st_size > MAX_FILE_SIZE:
                    raise VaultError(f"Not a file or exceeds 64 MiB: {path.name}")
                with path.open("rb") as stream:
                    item = vault.add(path.name, stream.read(MAX_FILE_SIZE + 1))
                print(f"Encrypted {item['name']} · {item['id']}")
        elif args.command == "export":
            _, data = vault.get(args.id)
            # Exclusive creation prevents accidental overwrites and symlink following.
            fd = os.open(args.destination, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(fd, "wb") as stream:
                stream.write(data)
            print(f"Exported plaintext to {args.destination}. Protect this copy separately.")
        elif args.command == "remove":
            vault.remove(args.id)
            print("Removed file and its key from the live catalog. Backups are unaffected.")
        elif args.command == "verify":
            result = vault.verify()
            print(json.dumps(result, indent=2))
            return 0 if result["ok"] else 1
        elif args.command == "passwd":
            print("Enter a new passphrase.")
            vault.change_passphrase(current, password(confirm=True))
            print("Passphrase updated. Existing backups still use their previous passphrase.")
        elif args.command == "backup":
            fd = os.open(args.destination, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(fd, "wb") as stream:
                vault.backup(stream)
            print(f"Encrypted snapshot saved to {args.destination}")
        elif args.command == "destroy":
            print(
                "Removes this vault's wrapped key. Backups and filesystem remnants may retain it."
            )
            vault.destroy(current, input("Type DESTROY to continue: "))
            print("Vault key removed. Encrypted objects remain on disk.")
        return 0
    except (VaultError, OSError, Timeout) as exc:
        print(f"SECUREX: {exc}", file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        return 130
    finally:
        if vault:
            vault.lock()


if __name__ == "__main__":
    raise SystemExit(main())
