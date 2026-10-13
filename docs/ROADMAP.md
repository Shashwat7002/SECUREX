# Roadmap

The working v0.1 baseline includes encrypted storage, a local dashboard, CLI workflows, integrity verification, backups, passphrase rotation, and automated tests.

Next, in order:

1. **Independent security review:** review the threat model, cryptographic format, HTTP boundary, memory handling, crash behavior, and platform permissions. Do not label the project audited before this happens.
2. **Streaming format v2:** design an authenticated chunk manifest, nonce/key strategy, truncation detection, bounded memory, and explicit v1 migration before increasing the 64 MiB limit.
3. **Guided restore:** validate archive paths, entry types, duplicates, decompression bounds, and format compatibility; verify recovery in a new directory before allowing promotion.
4. **Native distribution:** signed installers and an OS-keychain integration with a clearly documented recovery model. Preserve the CLI for automation.
5. **Durability and accessibility:** fault-injected power-loss tests, rollback strategy, screen-reader verification, keyboard-only journey tests, and encrypted backup scheduling.

Cloud sync, sharing, kernel drivers, and claims of guaranteed erasure are outside the current scope. Any new feature must preserve honest security claims and a usable offline core.
