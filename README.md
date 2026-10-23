# 🔐 VaultKey — Your Passwords, Locked Behind One Key

> **A desktop password manager built with Qt/WebEngine.**  
> Store credentials locally, encrypted with **Argon2id + AES-256-GCM**, and access them with a single master password.

[![Python](https://img.shields.io/badge/Python-3.10+-blue?logo=python)](https://python.org)
[![PySide6](https://img.shields.io/badge/PySide6-6.6+-green?logo=qt)](https://wiki.qt.io/Qt_for_Python)
[![C++](https://img.shields.io/badge/C%2B%2B-17-orange?logo=cplusplus)](https://isocpp.org)
[![Qt6](https://img.shields.io/badge/Qt6-Core%20%7C%20WebEngine-lightgrey?logo=qt)](https://qt.io)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Platform](https://img.shields.io/badge/Platform-Windows%20%7C%20Linux%20%7C%20macOS-red)]()
[![Encryption](https://img.shields.io/badge/Crypto-Argon2id%20%2B%20AES--256--GCM-purple)]()

---

## ✨ What is VaultKey?

VaultKey is a **local-first, offline password manager** that keeps your credentials encrypted on *your* device — not in the cloud. It wraps a modern HTML/CSS/JS frontend inside a Qt WebEngine view and connects it to a backend (Python **or** C++) through Qt's `QWebChannel`.

Everything stays on your machine. No telemetry. No accounts to create with a third party. You hold the only key.

---

## 🛡️ Security Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                      MASTER PASSWORD                        │
└─────────────────────────────────────────────────────────────┘
                           │
        ┌──────────────────┴──────────────────┐
        ▼                                     ▼
  Argon2id Hash                      Argon2id KDF
  (login verification)               (→ Key-Encryption-Key)
        │                                     │
        ▼                                     ▼
  Stored in DB              Encrypts the random 256-bit
                                    Vault Key
                                    (AES-256-GCM)
                                    │
                                    ▼
                              Vault Key (RAM only)
                                    │
                                    ▼
                         Each vault item encrypted individually
                              (AES-256-GCM)
```

### What's on disk vs. what's in memory

| Location | Stored? | Never Stored? |
|----------|---------|---------------|
| `vault.db` | Argon2id password hash, KEK salt, wrapped Vault Key, AES-256-GCM-encrypted vault items | ❌ Master password |
| RAM (session) | Plaintext Vault Key while logged in | ❌ Plaintext Vault Key after logout |
| Disk | Nothing readable without your master password | ✅ Zeroed on logout |

**Key design decisions:**
- 🔑 **Two separate secrets** from one password: one for proving who you are, one for unlocking the vault.
- 🔄 **Change your master password cheaply:** only the Vault Key wrapper is re-encrypted — every saved password stays untouched.
- 🧼 **Secure delete:** SQLite uses `secure_delete = ON` so removed rows are overwritten, not just unlinked.
- 🌐 **No remote access:** `LocalContentCanAccessRemoteUrls` is disabled — the embedded browser cannot phone home.
- 🔒 **Zeroed memory:** The Vault Key is overwritten with zeros in `logout()` and the destructor.

---

## 📦 What's Inside the Archive

```
passwd safe/
├── 🐍 main.py                    # Python/PySide6 desktop app
├── 📄 login.html                 # Sign-in / sign-up UI
├── 📄 dashboard.html             # Vault UI (flip cards, matrix bg)
├── 🗄️ vault.db                   # SQLite database (1 existing user: ujjal)
├── 📋 requirements.txt           # Python dependencies
├── 📖 AGENT_PROMPT_packaging.md  # Windows .exe packaging guide
├── ⚙️ .vscode/settings.json      # VS Code config
└── 🖥️ vaultkey-cpp/               # Native C++/Qt6 port
    ├── CMakeLists.txt
    ├── README.md
    ├── main.cpp
    ├── backend.h / backend.cpp
    ├── database.h / database.cpp
    ├── login.html (copy)
    └── dashboard.html (copy)
```

---

## 🚀 Quick Start

### Option 1: Python (PySide6) — fastest to try

```bash
# 1. Enter the folder
cd "passwd safe"

# 2. Install dependencies
pip install -r requirements.txt --break-system-packages

# 3. Run the app
python main.py
```

**Requirements:** Python 3.10+, PySide6>=6.6, argon2-cffi>=23.1, cryptography>=42.0

---

### Option 2: C++ / Qt6 — native build

```bash
# Linux (Ubuntu/Debian)
sudo apt install qt6-base-dev qt6-webengine-dev qt6-webchannel-dev \
                 libargon2-dev libssl-dev libsqlite3-dev cmake

mkdir build && cd build
cmake .. -DCMAKE_BUILD_TYPE=Release
make -j
./vaultkey
```

**Requirements:** Qt6 (Core, Widgets, WebEngineWidgets, WebChannel), OpenSSL, libargon2, SQLite3, CMake 3.19+

---

## 📖 Step-by-Step: How to Use It

### Step 1 — Launch the App
Double-click `vaultkey.exe` (Windows) or run `./vaultkey` / `python main.py` (Linux/macOS).  
You'll see the **login screen** with the VaultKey keyhole logo.

### Step 2 — Create Your First Account
1. Click **"Create one"** (or switch to the sign-up view).
2. Choose a username (3–32 characters).
3. Enter a master password (8+ characters — watch the strength meter).
4. Confirm the password and click **Create Account**.
5. Your account is created and a random Vault Key is generated behind the scenes.

> 💡 **Tip:** Pick a strong master password you won't forget. There is no "reset password" — if you lose it, your vault is unrecoverable.

### Step 3 — Sign In
1. Enter your username and master password.
2. Click **Sign In**.
3. The app unwraps your Vault Key in memory and opens the dashboard.

### Step 4 — Add Your First Password
1. On the dashboard, click the floating **"Add Password"** button (bottom right).
2. Fill in:
   - **Site / App name** (e.g. GitHub)
   - **Link** (optional, e.g. github.com)
   - **Email / Username** (optional)
   - **Password**
3. Click **Save password**.

### Step 5 — View / Reveal a Password
1. Find the item card in the vault grid.
2. **Click the card** — it flips over like a physical card.
3. The password is decrypted from the database and shown on the back.
4. Click **Copy** to copy it to your clipboard (it auto-clears after 30 seconds).
5. Click the card again to flip it back and hide the password.

### Step 6 — Edit or Delete
- **Delete:** Click the trash icon on a card and confirm.
- **Auto-lock:** The vault locks itself after 5 minutes of inactivity or when you minimize/hide the window.

### Step 7 — Log Out
Click **Log out** in the top bar. The Vault Key is zeroed from memory immediately.

---

## 🗄️ Database Notes

The included `vault.db` already contains one user:

| Field | Value |
|-------|-------|
| Username | `ujjal` |
| Password hash | Argon2id (`$argon2id$v=19$m=65536,t=3,p=2$...`) |
| Vault Key scheme | Active (new) |
| Saved items | 0 (empty) |

> ⚠️ You do **not** know `ujjal`'s master password. To test the full flow, create your own account.

The database schema is identical between the Python and C++ builds, so you can switch between them — just copy `vault.db` to the correct location:
- **Python:** next to `main.py`
- **C++:** OS app-data folder (`%APPDATA%/VaultKey` on Windows)

---

## 🎨 UI Features

| Feature | Description |
|---------|-------------|
| 🌙 Dark / ☀️ Light theme | Toggle in the top bar, saved to localStorage |
| 🃏 Flip-to-reveal cards | Click any item to flip and see the password |
| 📋 Copy-to-clipboard | One-click copy with auto-clear after 30s |
| ⏱️ Auto-lock | Locks after 5 minutes of inactivity |
| 🌧️ Matrix rain background | Subtle animated backdrop on the dashboard |
| 🔒 No right-click inspect | Casual tampering discouraged |

---

## 🔧 Packaging for Windows (Optional)

See `AGENT_PROMPT_packaging.md` for the full guide to producing:

1. **`VaultKeySetup.exe`** — a real installer (Inno Setup) that puts VaultKey in Program Files with Start Menu/Desktop shortcuts.
2. **`VaultKey-Portable.exe`** — a single-file portable build (Enigma Virtual Box) that runs with no install.

---

## 🤝 Contributing

Pull requests are welcome! Here's how to get started:

```bash
# Fork the repo, then clone your fork
git clone https://github.com/YOUR-USERNAME/VaultKey.git
cd VaultKey

# Create a feature branch
git checkout -b feature/your-feature-name

# Make changes, then commit
git add .
git commit -m "✨ add: your feature description"

# Push and open a PR
git push origin feature/your-feature-name
```

**Please:** Don't commit real passwords or your `vault.db` with actual data.

---

## 📄 License

MIT License — free to use, modify, and distribute. See `LICENSE` for details.

---

## ⚠️ Disclaimer

VaultKey encrypts your data locally with strong cryptography, but **you are responsible for your master password.** If you lose it, there is no recovery. Back up your `vault.db` file regularly if the data matters to you.

---

> Built with ❤️ for people who want their passwords under their own control — not in someone else's cloud.
