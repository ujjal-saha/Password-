"""
VaultKey - PySide6 desktop shell for login.html / dashboard.html
------------------------------------------------------------------
Connects the HTML/CSS/JS UI to a Python backend via QWebChannel.

AUTHENTICATION
    - Passwords are hashed with Argon2id (argon2-cffi) before being stored.
    - login() verifies the Argon2 hash. The plaintext master password is
      NEVER stored anywhere.

VAULT ENCRYPTION - Argon2id + random Vault Key + AES-256-GCM
    Authentication and vault encryption are two separate secrets derived
    from the same master password, so that verifying a login can never by
    itself hand you the encryption key.

        Master Password
              |
              v
        Argon2id  (password-verification hash - stored, used only by login())

        Master Password + kek_salt
              |
              v
        Argon2id KDF  --->  Key-Encryption-Key (KEK, 256-bit, RAM only)
              |
              v
        decrypts the stored, AES-256-GCM-wrapped random Vault Key
              |
              v
        Vault Key (256-bit, RAM only, never written to disk)
              |
              v
        AES-256-GCM encrypt/decrypt of individual vault item passwords

    On account creation: a random 256-bit Vault Key is generated once,
    encrypted under a freshly-derived KEK, and only that *encrypted* Vault
    Key is stored. Every vault item is then encrypted straight to the Vault
    Key (not to a key derived from the password), which is what makes a
    "change master password" flow cheap later - you only need to re-wrap the
    Vault Key under a new KEK, not re-encrypt every stored password.

    What's on disk: Argon2id password hash, KEK salt, AES-256-GCM-wrapped
    Vault Key, AES-256-GCM-encrypted vault entries, metadata.
    What's never on disk: the master password, the plaintext Vault Key, or
    any decrypted vault entry.

    On logout, self.session is cleared - the Vault Key disappears from
    memory at that point and nowhere else.

    Legacy accounts created before this scheme (PBKDF2 + Fernet) are
    migrated automatically the next time they log in - see
    Backend._migrate_legacy_account().

Install dependencies:
    pip install -r requirements.txt --break-system-packages

Run:
    python main.py

Folder layout expected:
    project/
      main.py
      login.html
      dashboard.html
      vault.db          (auto-created on first run)
"""

import sys
import os
import json
import base64
import sqlite3
from pathlib import Path

from PySide6.QtCore import QObject, Signal, Slot, QUrl
from PySide6.QtWidgets import QApplication, QMainWindow
from PySide6.QtWebEngineWidgets import QWebEngineView
# QWebEngineSettings lives in different modules depending on PySide6 build.
# Import defensively so the app can run on environments that expose it
# via QtWebEngineCore instead of QtWebEngineWidgets.
try:
    from PySide6.QtWebEngineCore import QWebEngineSettings
except Exception:
    QWebEngineSettings = None
from PySide6.QtWebChannel import QWebChannel

from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError, VerificationError, InvalidHashError
from argon2.low_level import hash_secret_raw, Type as Argon2Type

from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.exceptions import InvalidTag
from cryptography.fernet import Fernet, InvalidToken


BASE_DIR = Path(__file__).resolve().parent
DB_PATH = BASE_DIR / "vault.db"
LOGIN_HTML = BASE_DIR / "login.html"
DASHBOARD_HTML = BASE_DIR / "dashboard.html"

# Legacy PBKDF2 params - kept only so _migrate_legacy_account() can still
# decrypt vault items created under the old scheme, once, during migration.
PBKDF2_ITERATIONS = 390_000

# Current KDF parameters for new accounts and for upgrading existing ones.
#
# Bumping "version" (plus any field you want to strengthen) is all you need
# to trigger a transparent re-wrap: the next time that user logs in, login()
# will decrypt the Vault Key with the OLD parameters, then immediately
# re-encrypt it under the NEW parameters and persist them.  The user sees
# nothing; the Vault Key itself never changes - only the wrapper around it
# gets stronger.
#
# Versioning rules:
#   - Increment "version" whenever you change any parameter.
#   - Never decrease a cost parameter in a new version (that would weaken
#     security for all accounts that haven't re-wrapped yet).
#   - The old parameters are read from the database, so old accounts keep
#     working until they log in and get silently upgraded.
CURRENT_KDF_PARAMS: dict = {
    "version":     1,
    "type":        "argon2id",
    "time_cost":   4,
    "memory_cost": 131072,   # 128 MiB
    "parallelism": 4,
}

KEK_SALT_LEN = 16     # bytes
VAULT_KEY_LEN = 32    # bytes - 256-bit Vault Key
GCM_NONCE_LEN = 12    # bytes - 96-bit nonce, standard for AES-GCM


# ----------------------------------------------------------------------
# Database layer
# ----------------------------------------------------------------------
class UserDatabase:
    """SQLite storage for users and their encrypted vault items."""

    def __init__(self, db_path: Path):
        self.db_path = db_path
        self._init_db()

    def _connect(self):
        conn = sqlite3.connect(self.db_path)
        conn.execute("PRAGMA foreign_keys = ON")
        # Harden SQLite: use WAL and enable secure_delete where available so
        # deleted ciphertext has a lower chance of remaining on disk.
        try:
            conn.execute("PRAGMA journal_mode = WAL")
        except Exception:
            pass
        try:
            conn.execute("PRAGMA secure_delete = ON")
        except Exception:
            pass
        return conn

    def _init_db(self):
        with self._connect() as conn:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS users (
                    id                  INTEGER PRIMARY KEY AUTOINCREMENT,
                    username            TEXT UNIQUE NOT NULL,
                    password_hash       TEXT NOT NULL,
                    kdf_salt            TEXT,
                    kek_salt            TEXT,
                    encrypted_vault_key TEXT,
                    kdf_params          TEXT,
                    created_at          TEXT DEFAULT CURRENT_TIMESTAMP
                )
                """
            )
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS vault_items (
                    id                  INTEGER PRIMARY KEY AUTOINCREMENT,
                    user_id             INTEGER NOT NULL,
                    name                TEXT NOT NULL,
                    url                 TEXT,
                    username            TEXT,
                    encrypted_password  TEXT NOT NULL,
                    created_at          TEXT DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE
                )
                """
            )
            conn.commit()
        self._migrate_schema()

    def _migrate_schema(self):
        """Adds columns that post-date the initial schema, all nullable so
        existing rows are unaffected until they log in and get upgraded.
          kek_salt / encrypted_vault_key - added with the Argon2id + Vault Key
            + AES-256-GCM scheme; absence marks a "legacy" PBKDF2+Fernet account.
          kdf_params - JSON blob of the Argon2id cost parameters used when the
            KEK was last derived; absence (or a lower version number) triggers a
            transparent re-wrap on the next login with CURRENT_KDF_PARAMS."""
        with self._connect() as conn:
            cols = {row[1] for row in conn.execute("PRAGMA table_info(users)")}
            if "kek_salt" not in cols:
                conn.execute("ALTER TABLE users ADD COLUMN kek_salt TEXT")
            if "encrypted_vault_key" not in cols:
                conn.execute("ALTER TABLE users ADD COLUMN encrypted_vault_key TEXT")
            if "kdf_params" not in cols:
                conn.execute("ALTER TABLE users ADD COLUMN kdf_params TEXT")
            conn.commit()
        # Ensure vault_items has a `username` column for storing account/email
        with self._connect() as conn:
            vcols = {row[1] for row in conn.execute("PRAGMA table_info(vault_items)")}
            if "username" not in vcols:
                conn.execute("ALTER TABLE vault_items ADD COLUMN username TEXT")
            conn.commit()

    # ---------------- users ----------------
    def username_exists(self, username: str) -> bool:
        with self._connect() as conn:
            cur = conn.execute("SELECT 1 FROM users WHERE username = ?", (username,))
            return cur.fetchone() is not None

    def create_user(self, username: str, password_hash: str, kek_salt_b64: str,
                    encrypted_vault_key_b64: str, kdf_params_json: str) -> None:
        with self._connect() as conn:
            conn.execute(
                """INSERT INTO users (username, password_hash, kdf_salt, kek_salt, encrypted_vault_key, kdf_params)
                   VALUES (?, ?, '', ?, ?, ?)""",
                (username, password_hash, kek_salt_b64, encrypted_vault_key_b64, kdf_params_json),
            )
            conn.commit()

    def get_user(self, username: str):
        """Returns (id, password_hash, kdf_salt_b64, kek_salt_b64,
        encrypted_vault_key_b64, kdf_params_json) or None.
        kdf_salt_b64 is only meaningful for legacy (pre-migration) accounts.
        kdf_params_json is None on accounts that pre-date versioning - they will
        be transparently upgraded to CURRENT_KDF_PARAMS on next login."""
        with self._connect() as conn:
            cur = conn.execute(
                """SELECT id, password_hash, kdf_salt, kek_salt,
                          encrypted_vault_key, kdf_params
                   FROM users WHERE username = ?""",
                (username,),
            )
            return cur.fetchone()

    def update_password_hash(self, username: str, new_hash: str) -> None:
        with self._connect() as conn:
            conn.execute(
                "UPDATE users SET password_hash = ? WHERE username = ?",
                (new_hash, username),
            )
            conn.commit()

    def upgrade_user_to_vault_key_scheme(self, user_id: int, kek_salt_b64: str,
                                         encrypted_vault_key_b64: str, kdf_params_json: str) -> None:
        """Called once per account, at the end of legacy (PBKDF2+Fernet) migration."""
        with self._connect() as conn:
            conn.execute(
                """UPDATE users SET kdf_salt = '', kek_salt = ?,
                          encrypted_vault_key = ?, kdf_params = ? WHERE id = ?""",
                (kek_salt_b64, encrypted_vault_key_b64, kdf_params_json, user_id),
            )
            conn.commit()

    def update_vault_key_and_params(self, user_id: int, kek_salt_b64: str,
                                    encrypted_vault_key_b64: str, kdf_params_json: str) -> None:
        """Re-persists a Vault Key wrapped under new (stronger) KDF parameters.
        Called by login() when CURRENT_KDF_PARAMS has been bumped since the
        last time this account wrapped its key."""
        with self._connect() as conn:
            conn.execute(
                """UPDATE users SET kek_salt = ?, encrypted_vault_key = ?,
                          kdf_params = ? WHERE id = ?""",
                (kek_salt_b64, encrypted_vault_key_b64, kdf_params_json, user_id),
            )
            conn.commit()

    # ---------------- vault items ----------------
    def add_vault_item(self, user_id: int, name: str, url: str, username: str, encrypted_password: str) -> int:
        with self._connect() as conn:
            cur = conn.execute(
                "INSERT INTO vault_items (user_id, name, url, username, encrypted_password) VALUES (?, ?, ?, ?, ?)",
                (user_id, name, url, username or '', encrypted_password),
            )
            conn.commit()
            return cur.lastrowid

    def get_vault_items(self, user_id: int):
        """Returns list of (id, name, url, username, created_at) - NOT passwords."""
        with self._connect() as conn:
            cur = conn.execute(
                "SELECT id, name, url, username, created_at FROM vault_items WHERE user_id = ? ORDER BY created_at DESC",
                (user_id,),
            )
            return cur.fetchall()

    def get_encrypted_password(self, item_id: int, user_id: int):
        with self._connect() as conn:
            cur = conn.execute(
                "SELECT encrypted_password FROM vault_items WHERE id = ? AND user_id = ?",
                (item_id, user_id),
            )
            row = cur.fetchone()
            return row[0] if row else None

    def get_all_vault_items_raw(self, user_id: int):
        """Returns [(id, encrypted_password), ...] for every item owned by
        this user - used only during legacy-account migration."""
        with self._connect() as conn:
            cur = conn.execute(
                "SELECT id, encrypted_password FROM vault_items WHERE user_id = ?",
                (user_id,),
            )
            return cur.fetchall()

    def update_vault_item_password(self, item_id: int, encrypted_password: str) -> None:
        with self._connect() as conn:
            conn.execute(
                "UPDATE vault_items SET encrypted_password = ? WHERE id = ?",
                (encrypted_password, item_id),
            )
            conn.commit()

    def delete_vault_item(self, item_id: int, user_id: int) -> bool:
        with self._connect() as conn:
            cur = conn.execute(
                "DELETE FROM vault_items WHERE id = ? AND user_id = ?",
                (item_id, user_id),
            )
            conn.commit()
            return cur.rowcount > 0


# ----------------------------------------------------------------------
# Backend exposed to JavaScript via QWebChannel
# ----------------------------------------------------------------------
class Backend(QObject):
    # Signals used by login.html / signup flow.
    loginResult = Signal(bool, str)
    createAccountResult = Signal(bool, str)

    def __init__(self, db: UserDatabase):
        super().__init__()
        self.db = db
        self.session = None  # dict: user_id, username, vault_key (bytes)  (cleared on logout)

        self.hasher = PasswordHasher(
            time_cost=3,
            memory_cost=65536,  # 64 MB
            parallelism=2,
            hash_len=32,
            salt_len=16,
        )

    # ---------------- key derivation (vault encryption, NOT login auth) ----------------
    @staticmethod
    def _derive_kek(password: str, salt: bytes, params: dict | None = None) -> bytes:
        """Argon2id: master password + kek_salt -> 256-bit Key-Encryption-Key.
        This never touches disk; it only exists long enough to unwrap (or,
        on account creation, wrap) the random Vault Key.
        Pass params=None to use CURRENT_KDF_PARAMS (new accounts / re-wrap).
        Pass the stored params dict to reproduce a KEK derived under older settings
        (needed to decrypt the existing wrapped Vault Key before upgrading it)."""
        p = params if params is not None else CURRENT_KDF_PARAMS
        return hash_secret_raw(
            secret=password.encode("utf-8"),
            salt=salt,
            time_cost=p["time_cost"],
            memory_cost=p["memory_cost"],
            parallelism=p["parallelism"],
            hash_len=VAULT_KEY_LEN,
            type=Argon2Type.ID,
        )

    @staticmethod
    def _params_need_upgrade(kdf_params_json: str | None) -> bool:
        """True when stored KDF params are absent or on an older version than
        CURRENT_KDF_PARAMS, which means we should re-wrap the Vault Key after
        login using the stronger current settings."""
        if not kdf_params_json:
            return True
        try:
            stored = json.loads(kdf_params_json)
            return int(stored.get("version", 0)) < int(CURRENT_KDF_PARAMS["version"])
        except (json.JSONDecodeError, TypeError, ValueError):
            return True

    @staticmethod
    def _aes_encrypt(key: bytes, plaintext: bytes) -> str:
        """AES-256-GCM encrypt with a fresh random nonce each call. Returns
        base64(nonce || ciphertext_with_tag) as a single string, ready to
        store in a TEXT column."""
        nonce = os.urandom(GCM_NONCE_LEN)
        ciphertext = AESGCM(key).encrypt(nonce, plaintext, None)
        return base64.b64encode(nonce + ciphertext).decode("ascii")

    @staticmethod
    def _aes_decrypt(key: bytes, blob_b64: str) -> bytes:
        raw = base64.b64decode(blob_b64)
        nonce, ciphertext = raw[:GCM_NONCE_LEN], raw[GCM_NONCE_LEN:]
        return AESGCM(key).decrypt(nonce, ciphertext, None)

    @staticmethod
    def _derive_legacy_fernet_key(password: str, salt: bytes) -> bytes:
        """PBKDF2-HMAC-SHA256, used ONLY to read vault items that were
        encrypted under the old (pre-Vault-Key) scheme, during migration."""
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=PBKDF2_ITERATIONS,
        )
        raw_key = kdf.derive(password.encode("utf-8"))
        return base64.urlsafe_b64encode(raw_key)  # Fernet requires urlsafe-b64, 32 bytes

    def _migrate_legacy_account(self, user_id: int, password: str, kdf_salt_b64: str):
        """One-time upgrade path for accounts created under the old
        PBKDF2 + Fernet scheme. Runs at successful login, while the
        plaintext password is still in hand:
          1. Derive the old Fernet key and decrypt every existing vault item.
          2. Generate a fresh KEK salt + random Vault Key, per the new scheme.
          3. Re-encrypt every item straight to the new Vault Key (AES-GCM).
          4. Persist the wrapped Vault Key and clear the legacy salt.
        Returns the new plaintext Vault Key (bytes) for the caller to keep in
        session, or None if the legacy data couldn't be read at all (e.g. a
        corrupted row) - the account can't be migrated automatically at that
        point and should be treated as a login failure.
        """
        try:
            legacy_salt = base64.b64decode(kdf_salt_b64)
            legacy_fernet = Fernet(self._derive_legacy_fernet_key(password, legacy_salt))
        except Exception:
            return None

        decrypted_items = {}
        for item_id, encrypted in self.db.get_all_vault_items_raw(user_id):
            try:
                decrypted_items[item_id] = legacy_fernet.decrypt(encrypted.encode("ascii"))
            except InvalidToken:
                # Can't recover this one item's plaintext without the old
                # key context being wrong somehow; leave it as-is rather
                # than lose the row outright.
                continue

        kek_salt = os.urandom(KEK_SALT_LEN)
        kek = self._derive_kek(password, kek_salt)
        # store the Vault Key in a mutable buffer so we can overwrite it later
        vault_key = bytearray(os.urandom(VAULT_KEY_LEN))
        encrypted_vault_key = self._aes_encrypt(kek, bytes(vault_key))

        for item_id, plaintext in decrypted_items.items():
            self.db.update_vault_item_password(item_id, self._aes_encrypt(bytes(vault_key), plaintext))

        self.db.upgrade_user_to_vault_key_scheme(
            user_id,
            base64.b64encode(kek_salt).decode("ascii"),
            encrypted_vault_key,
            json.dumps(CURRENT_KDF_PARAMS),
        )
        return vault_key

    # ---------------- validation helpers ----------------
    @staticmethod
    def _validate_username(username: str):
        username = (username or "").strip()
        if not username:
            return None, "Username cannot be empty."
        if len(username) < 3:
            return None, "Username must be at least 3 characters."
        if len(username) > 32:
            return None, "Username must be 32 characters or fewer."
        return username, None

    @staticmethod
    def _validate_password(password: str):
        if not password:
            return "Password cannot be empty."
        if len(password) < 8:
            return "Password must be at least 8 characters."
        return None

    # ================= AUTH: called from login.html =================
    @Slot(str, str)
    def login(self, username: str, password: str):
        username, err = self._validate_username(username)
        if err:
            self.loginResult.emit(False, err)
            return

        row = self.db.get_user(username)
        if row is None:
            self.loginResult.emit(False, "Invalid username or password.")
            return

        user_id, stored_hash, kdf_salt_b64, kek_salt_b64, encrypted_vault_key_b64, kdf_params_json = row

        try:
            self.hasher.verify(stored_hash, password)
        except VerifyMismatchError:
            self.loginResult.emit(False, "Invalid username or password.")
            return
        except (VerificationError, InvalidHashError):
            self.loginResult.emit(False, "Account data is corrupted. Contact support.")
            return

        if self.hasher.check_needs_rehash(stored_hash):
            new_hash = self.hasher.hash(password)
            self.db.update_password_hash(username, new_hash)

        # Unwrap the Vault Key now, while we still have the plaintext master
        # password in hand - then never store the password itself.
        if kek_salt_b64 and encrypted_vault_key_b64:
            # Decrypt using whatever parameters were in use when the KEK was
            # last derived - NOT necessarily CURRENT_KDF_PARAMS (it may have
            # been bumped since this account last logged in).
            try:
                stored_params = json.loads(kdf_params_json) if kdf_params_json else None
            except (json.JSONDecodeError, TypeError):
                stored_params = None

            kek = self._derive_kek(password, base64.b64decode(kek_salt_b64), stored_params)
            try:
                # decrypted vault_key is bytes; convert to mutable bytearray
                vault_key = bytearray(self._aes_decrypt(kek, encrypted_vault_key_b64))
            except InvalidTag:
                self.loginResult.emit(False, "Account data is corrupted. Contact support.")
                return

            # Transparent parameter upgrade: if CURRENT_KDF_PARAMS has been
            # bumped since the Vault Key was last wrapped, re-derive a fresh
            # KEK under the new settings and re-persist the wrapped Vault Key.
            # The Vault Key itself is unchanged; only its wrapper gets stronger.
            if self._params_need_upgrade(kdf_params_json):
                new_kek_salt = os.urandom(KEK_SALT_LEN)
                new_kek = self._derive_kek(password, new_kek_salt)   # uses CURRENT_KDF_PARAMS
                new_wrapped = self._aes_encrypt(new_kek, bytes(vault_key))
                self.db.update_vault_key_and_params(
                    user_id,
                    base64.b64encode(new_kek_salt).decode("ascii"),
                    new_wrapped,
                    json.dumps(CURRENT_KDF_PARAMS),
                )
        else:
            # Pre-upgrade account (old PBKDF2 + Fernet scheme) - migrate it
            # to the Vault Key scheme now, one time, then proceed as normal.
            vault_key = self._migrate_legacy_account(user_id, password, kdf_salt_b64)
            if vault_key is None:
                self.loginResult.emit(False, "Account data is corrupted. Contact support.")
                return

        self.session = {
            "user_id": user_id,
            "username": username,
            "vault_key": vault_key,  # mutable bytearray
        }

        self.loginResult.emit(True, "OK")

    @Slot(str, str)
    def createAccount(self, username: str, password: str):
        username, err = self._validate_username(username)
        if err:
            self.createAccountResult.emit(False, err)
            return

        err = self._validate_password(password)
        if err:
            self.createAccountResult.emit(False, err)
            return

        if self.db.username_exists(username):
            self.createAccountResult.emit(False, "That username is already taken.")
            return

        password_hash = self.hasher.hash(password)

        # Argon2id(password, kek_salt) -> KEK; generate a random Vault Key;
        # wrap the Vault Key under the KEK with AES-256-GCM. Only the wrapped
        # Vault Key is ever stored - the KEK and the plaintext Vault Key both
        # stay in memory just long enough to do this.
        kek_salt = os.urandom(KEK_SALT_LEN)
        kek = self._derive_kek(password, kek_salt)
        # use a mutable buffer for the Vault Key so it can be zeroized later
        vault_key = bytearray(os.urandom(VAULT_KEY_LEN))
        encrypted_vault_key = self._aes_encrypt(kek, bytes(vault_key))

        try:
            self.db.create_user(
                username,
                password_hash,
                base64.b64encode(kek_salt).decode("ascii"),
                encrypted_vault_key,
                json.dumps(CURRENT_KDF_PARAMS),
            )
        except sqlite3.IntegrityError:
            self.createAccountResult.emit(False, "That username is already taken.")
            return

        self.createAccountResult.emit(True, "Account created.")

    # ================= SESSION: called from dashboard.html =================
    @Slot(result=str)
    def getCurrentUser(self):
        if not self.session:
            return json.dumps({"loggedIn": False})
        return json.dumps({"loggedIn": True, "username": self.session["username"]})

    @Slot(result=bool)
    def logout(self):
        # Overwrite the Vault Key in memory (best-effort) before clearing session.
        if self.session and isinstance(self.session, dict):
            vk = self.session.get("vault_key")
            try:
                if isinstance(vk, (bytearray, memoryview)):
                    for i in range(len(vk)):
                        vk[i] = 0
            except Exception:
                pass
        self.session = None
        return True

    # ================= VAULT: called from dashboard.html =================
    @Slot(result=str)
    def getVaultItems(self):
        if not self.session:
            return json.dumps({"success": False, "message": "Not logged in.", "items": []})

        rows = self.db.get_vault_items(self.session["user_id"])
        items = [
            {"id": r[0], "name": r[1], "url": r[2] or "", "user": r[3] or "", "createdAt": r[4]}
            for r in rows
        ]
        return json.dumps({"success": True, "items": items})

    @Slot(str, str, str, str, result=str)
    def addVaultItem(self, name: str, url: str, username: str, password: str):
        if not self.session:
            return json.dumps({"success": False, "message": "Not logged in."})

        name = (name or "").strip()
        if not name:
            return json.dumps({"success": False, "message": "Item name cannot be empty."})
        if not password:
            return json.dumps({"success": False, "message": "Password cannot be empty."})

        encrypted = self._aes_encrypt(bytes(self.session["vault_key"]), password.encode("utf-8"))
        new_id = self.db.add_vault_item(self.session["user_id"], name, (url or "").strip(), (username or "").strip(), encrypted)

        return json.dumps({"success": True, "message": "Saved.", "id": new_id})

    @Slot(int, result=str)
    def revealPassword(self, item_id: int):
        if not self.session:
            return json.dumps({"success": False, "message": "Not logged in."})

        encrypted = self.db.get_encrypted_password(item_id, self.session["user_id"])
        if encrypted is None:
            return json.dumps({"success": False, "message": "Item not found."})

        try:
            plaintext = self._aes_decrypt(bytes(self.session["vault_key"]), encrypted).decode("utf-8")
        except (InvalidTag, ValueError):
            return json.dumps({"success": False, "message": "Could not decrypt this item."})

        return json.dumps({"success": True, "password": plaintext})

    @Slot(int, result=str)
    def deleteVaultItem(self, item_id: int):
        if not self.session:
            return json.dumps({"success": False, "message": "Not logged in."})

        deleted = self.db.delete_vault_item(item_id, self.session["user_id"])
        if not deleted:
            return json.dumps({"success": False, "message": "Item not found."})

        return json.dumps({"success": True, "message": "Deleted."})


# ----------------------------------------------------------------------
# Main window
# ----------------------------------------------------------------------
class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("VaultKey")
        self.resize(1100, 720)

        self.db = UserDatabase(DB_PATH)
        self.backend = Backend(self.db)

        self.view = QWebEngineView(self)
        # Restrict the embedded web view from loading remote URLs from local content
        try:
            if QWebEngineSettings is not None and hasattr(QWebEngineSettings, "LocalContentCanAccessRemoteUrls"):
                self.view.settings().setAttribute(QWebEngineSettings.LocalContentCanAccessRemoteUrls, False)
        except Exception:
            # be permissive if the attribute or enum is unavailable on this PySide build
            pass
        self.setCentralWidget(self.view)

        self.channel = QWebChannel(self.view.page())
        self.channel.registerObject("backend", self.backend)
        self.view.page().setWebChannel(self.channel)

        if not LOGIN_HTML.exists():
            raise FileNotFoundError(f"login.html not found at {LOGIN_HTML}")

        self.view.load(QUrl.fromLocalFile(str(LOGIN_HTML)))


def main():
    app = QApplication(sys.argv)
    window = MainWindow()
    window.show()
    sys.exit(app.exec())


if __name__ == "__main__":
    main()
