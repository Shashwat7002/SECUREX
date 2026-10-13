# Contributing

Use Python 3.11 or newer and install with `python -m pip install -e '.[dev]'`.

Before submitting changes, run:

```bash
ruff check src tests
ruff format --check src tests
pytest -q
python -m build
```

Use disposable vaults and synthetic data when testing. Never commit live vault data, passphrases, launch links, exported private files, or local machine paths. Changes to cryptography must include a security-model update and regression tests for failure cases, not just successful round trips.

Keep storage behavior in `vault.py`, HTTP behavior in `web.py`, and presentation in `static/`. Avoid adding cloud dependencies or telemetry. Maintain mobile layouts, keyboard focus, reduced-motion behavior, and readable error messages.

A change to persisted bytes needs an explicit format-version/migration decision. Do not silently reinterpret existing vaults. Review concurrency, interruption, backups, and old-key implications.

For manual browser checks, create a disposable vault, import an empty file and a Unicode filename, test filtering and export, verify integrity, rotate the passphrase, lock/unlock, and check a narrow viewport. Use only sample files in screenshots.
