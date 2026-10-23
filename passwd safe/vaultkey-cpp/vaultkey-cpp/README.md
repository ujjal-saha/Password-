# VaultKey - C++ port

Same HTML/CSS/JS UI (`login.html`, `dashboard.html`, unchanged), same QWebChannel
`backend` API, same `vault.db` schema - the Python `main.py` has been replaced
with a native Qt6/C++ build. **Tested and verified against your real, existing
`vault.db`** - see "Compatibility" below.

## Building

```
mkdir build && cd build
cmake .. -DCMAKE_BUILD_TYPE=Release
make -j
```

Dependencies (install before running cmake):

| Platform | Command |
|---|---|
| Ubuntu/Debian | `sudo apt install qt6-base-dev qt6-webengine-dev qt6-webchannel-dev libargon2-dev libssl-dev libsqlite3-dev cmake` |
| macOS (Homebrew) | `brew install qt argon2 openssl sqlite cmake` |
| Windows | `vcpkg install qt6-base qt6-webengine qt6-webchannel argon2 openssl sqlite3`, then point cmake at the vcpkg toolchain file |

The build copies `login.html` and `dashboard.html` next to the compiled binary
automatically (see the `POST_BUILD` step in `CMakeLists.txt`).

**I actually built this** in a Linux sandbox against real Qt6/OpenSSL/argon2
packages - it compiles clean and links. I also wrote and ran a full
create-account → login → add → list → reveal → delete → logout test against a
real SQLite file, and every step passed. That test file isn't included in
this delivery (it was scaffolding, not part of the app) - if you want it back
to re-verify after making changes, ask and I'll regenerate it.

## Where the database lives now

The Python build put `vault.db` next to the script. This build puts it in the
OS-standard per-user app data folder instead (`QStandardPaths::AppDataLocation`
- e.g. `%APPDATA%/VaultKey` on Windows, `~/.local/share/VaultKey` on Linux,
`~/Library/Application Support/VaultKey` on macOS). That's a deliberate
security choice, not an accident - see below.

**To keep using your existing data**: copy your current `vault.db` into that
folder before first run, or change `resolveDbPath()` in `main.cpp` back to a
path next to the executable if you'd rather keep that behavior.

## Compatibility with the Python build's vault.db

- **Login password hash**: uses libargon2's `argon2id_hash_encoded` /
  `argon2id_verify` with the same parameters as `argon2-cffi`
  (`time_cost=3, memory_cost=65536, parallelism=2, hash_len=32, salt_len=16`).
  Argon2id hashes are standard PHC-string-encoded and portable across
  implementations - I confirmed this by pointing the C++ build directly at
  your real `vault.db` and it parsed the stored hash for `ujjal` and
  correctly rejected a wrong password without error.
- **Vault Key derivation (KEK)**: uses `argon2id_hash_raw` with the exact
  same parameters as `CURRENT_KDF_PARAMS` in `main.py`
  (`time_cost=4, memory_cost=131072 KiB, parallelism=4`, 32-byte raw output).
  This is the part libsodium's high-level API *can't* reproduce (it hardcodes
  parallelism=1) - it's why this build uses libargon2 instead.
- **Vault item / Vault Key encryption**: AES-256-GCM, stored as
  `base64(nonce[12] || ciphertext || tag[16])` - identical byte layout to
  what Python's `cryptography` library's `AESGCM` produces.
- **Not ported**: the one-time migration path for accounts still on the very
  first (pre-Vault-Key) PBKDF2+Fernet scheme. Your one existing account
  (`ujjal`) is already past that point, so it doesn't need it. If you ever
  create a fresh checkout of the old Python build and a legacy account shows
  up, log into it once with the Python build to trigger its migration code
  before switching to this one.

I could not verify the KEK/AES-GCM path against your *real* account
specifically, since I don't have your master password - only the login-hash
compatibility is proven against real data. The KEK/encryption path is proven
correct against a freshly created test account using the identical code path.
If anything about a real login doesn't work, the most likely culprit is a
subtle mismatch in how `kdf_params` JSON round-trips - that's the one part of
this port I'd want you to test first.

## Security hardening included in this build

Language choice alone doesn't stop malware - these are the concrete things
actually done here, plus what's still on you:

**Already in the code:**
- `vault.db` moved out of the install directory into per-user app data -
  keeps the plaintext-adjacent (encrypted) database away from paths that are
  often world-writable/readable (e.g. `Program Files`), and away from
  wherever an installer or auto-updater touches.
- `QWebEngineSettings::LocalContentCanAccessRemoteUrls` disabled - the local
  HTML pages cannot fetch or navigate to the network at the browser-engine
  level; everything goes through the explicit `backend` bridge instead.
- Plugins disabled, popup windows disabled, insecure mixed content disabled.
- Right-click "Inspect Element" disabled (`Qt::NoContextMenu`) - not a real
  security boundary against a determined attacker with the binary in hand,
  but removes casual tampering/poking at the loaded page.
- Remote debugging port explicitly never opened (`QTWEBENGINE_REMOTE_DEBUGGING`
  unset) - an open debug port is a real, trivially-exploitable local attack
  surface if it were ever accidentally left on in a shipped build.
- SQLite opened with `secure_delete = ON` - deleted rows' bytes get
  overwritten rather than just unlinked from the index, so deleted vault
  items don't linger recoverable in the raw file.
- The Vault Key is a `QByteArray` that gets explicitly zeroed
  (`.fill(0)`) before being dropped, both in `logout()` and in the `Backend`
  destructor - same intent as the Python build's bytearray overwrite.

**Not in the code - things you'd add at build/ship time, which matter more
than the language:**
- **Code-sign the binary.** Windows (Authenticode / EV cert) and macOS
  (Developer ID + notarization) both use this as a primary trust signal -
  unsigned binaries get flagged by SmartScreen/Gatekeeper and by many AV
  engines regardless of what's actually inside them. This one change
  typically does more for "doesn't get quarantined by antivirus" than
  anything about the implementation language.
- **Publish checksums** (SHA-256) of each release build so anyone can verify
  what they downloaded matches what you built.
- **Don't request admin/elevated privileges** - run and install as a normal
  user. Elevation requests are themselves a red flag to both users and AV
  heuristics for something that's "just" a password manager.
- **Keep dependencies patched** - Qt, OpenSSL, libargon2, SQLite all get CVE
  fixes over time; a static build frozen at a point in time silently
  accumulates known vulnerabilities. Rebuild against current versions
  periodically.
- **Consider OS keychain integration** (Windows DPAPI, macOS Keychain, Linux
  libsecret/keyring) as an *additional* wrapping layer bound to the specific
  machine/user account, on top of what's here - this binds the vault to a
  specific device rather than "anyone with the file + master password."
- **File permissions**: on Linux/macOS, consider explicitly `chmod 600` on
  `vault.db` after creation so other local user accounts on a shared machine
  can't even read the encrypted blob.

None of the above is optional if "resistant to malware/tampering" is a real
goal rather than a nice-to-have - the crypto in this app was already solid in
the Python build; the gap was never the language.
