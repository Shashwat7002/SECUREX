# Changelog

## 0.1.0 — 2026-10-13

First working release of SECUREX, replacing the initial project placeholder.

- Offline dashboard with vault setup, locking, drag-and-drop imports, search, category filters, file export, and session activity.
- AES-256-GCM envelope encryption, encrypted metadata, per-file keys, scrypt passphrase protection, and format versioning.
- CLI covering the complete vault lifecycle.
- Authenticated integrity checks, encrypted snapshot export, passphrase rotation, and explicit key-removal controls.
- Atomic writes, cross-process locking, local HTTP host/origin/session boundaries, automatic inactivity locking, and memory-only plaintext imports.
- Automated regression tests, cross-platform CI, dependency auditing, installable Python distributions, and security/architecture documentation.

Limits: early release without independent audit; 64 MiB per file; no guaranteed forensic erasure; no protection for compromised or unlocked devices. See the security model.
