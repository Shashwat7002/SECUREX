# Security model

SECUREX v0.1 is an experimental local file vault, not an audited security product. This document describes implementation guarantees and explicit limits, not a certification.

## Intended protection

An attacker who obtains a locked vault directory should not learn file contents, filenames, checksums, or recorded import times without the passphrase or key material. A long, unpredictable passphrase is essential: an attacker with `key.json` can attempt offline guesses.

The operating system, browser, Python runtime, cryptography library, and user account are trusted. A separate OS user should not receive vault directory access. On POSIX, newly created vault directories use 0700 and written files use 0600. Windows ACLs follow the parent directory; SECUREX does not configure ACLs. Protect restored directories with appropriate OS permissions.

## Cryptographic construction

- Random values come from Python's `secrets` module.
- A 32-byte random master key encrypts the catalog using AES-256-GCM.
- A wrapping key is derived from the UTF-8 passphrase using scrypt, N=2^17, r=8, p=1, output length 32, and a fresh random 16-byte salt. Approximate KDF memory use is 128 MiB.
- The wrapping key encrypts the master key with AES-256-GCM. A passphrase change replaces the salt and wrapped master key atomically. File ciphertext does not change.
- Every import receives a fresh random 32-byte file key and 16-byte opaque file ID. File keys are stored only inside the encrypted catalog.
- Each encryption uses a fresh random 12-byte nonce and a full 16-byte GCM authentication tag. Random nonces have a probabilistic collision bound; do not use this early implementation for enormous, high-churn archives.
- Associated data binds objects to the format version, purpose, vault ID, and file ID as applicable. Swapping file objects fails authentication.
- SHA-256 and size checks are secondary integrity checks against authenticated catalog metadata. AEAD authentication, not an unkeyed checksum alone, establishes authenticity.

References: [cryptography AESGCM documentation](https://cryptography.io/en/latest/hazmat/primitives/aead/#cryptography.hazmat.primitives.ciphers.aead.AESGCM), [cryptography scrypt documentation](https://cryptography.io/en/latest/hazmat/primitives/key-derivation-functions/#scrypt).

## Local browser boundary

The service binds to 127.0.0.1 only. It rejects an unexpected Host header to mitigate DNS rebinding. Every modifying API request must include the exact local Origin. Every vault API request requires a session cookie obtained by exchanging the random launch token. The cookie is HttpOnly and SameSite=Strict. Because transport is local HTTP, it is not a Secure cookie. The launch token is a bearer credential; do not share it.

There is no CORS grant. Static responses set a restrictive Content Security Policy, deny framing, prevent MIME sniffing, omit referrers, and disable caching. File exports use attachment disposition and application/octet-stream. User filenames enter the DOM via textContent, never HTML interpolation.

The service is for a single trusted local user, not hosting, LAN access, containers exposed on public ports, reverse proxies, or multiple untrusted tenants. Same-user malware can bypass this boundary. Loopback HTTP does not defend against privileged local interception. Browser extensions and browser vulnerabilities remain outside the threat model.

## Keys, memory, and inactivity

Unlocked keys and plaintext are present in process memory. Python and browser runtimes cannot guarantee zeroization of immutable values, garbage collection copies, or downloads. Locking drops application references; it does not prove the previous bytes were erased. OS swap and crash dumps may capture sensitive memory. Full-disk encryption is a useful additional layer.

A server thread checks for five minutes of inactivity and drops vault key references without requiring a browser request. Actual API operations reset inactivity; status polling does not. A long operation already holding the server lock must finish before the timer can lock the vault. Closing the tab does not immediately stop the server; lock explicitly or stop the process.

Passphrase rotation does not revoke keys already held by another unlocked process, nor does it change old backups. Stop other running clients when rotating access.

## Plaintext handling

Imports and authenticated decryption are bounded to 64 MiB per file and handled in memory. Werkzeug multipart file streams use BytesIO, and Waitress's input spill threshold exceeds the maximum accepted request size. There is no intentional plaintext upload staging file. Concurrent connections and cryptographic copies increase peak RAM. This does not prevent OS swapping.

Encrypted backup assembly may use a temporary file containing ciphertext and wrapped keys. Exports intentionally create plaintext files. Originals, thumbnails generated elsewhere, filesystem indexes, browser downloads, and external copies remain outside the vault's control.

## Deletion and key removal

Removing a file atomically rewrites the encrypted catalog without that file's key, then unlinks the encrypted object. Removing the vault key unlinks its wrapped-key file. Neither action uses overwrite-based secure deletion or guarantees forensic erasure.

Recovery may remain possible from old encrypted catalogs, wrapped keys, backup archives, snapshots, filesystem journals, SSD remapping, swap, RAM, and other unlocked processes. Backups intentionally preserve recoverability. A backup predating deletion can restore the deleted file. A backup predating passphrase rotation retains its earlier passphrase.

## Exposed metadata and attacks outside scope

Visible metadata includes the format version, vault ID, salt, wrapped key, number and approximate sizes of encrypted objects, filesystem timestamps, and filesystem access patterns. No padding or traffic-oblivious storage is implemented.

SECUREX detects authenticated ciphertext alteration and missing referenced objects. It does not detect rollback of an entire valid earlier vault snapshot. It does not guarantee availability against deletion, ransomware, disk failure, or malicious local modification. It has no hardware-backed keystore, secure enclave, recovery escrow, cloud sync, sharing protocol, or independent audit.

Use test data first. Keep verified backups. Do not claim stronger guarantees than this document.
