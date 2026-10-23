#pragma once

#include <QObject>
#include <QString>
#include <QByteArray>
#include <memory>
#include <optional>
#include "database.h"

// Argon2id parameters for the login password-verification hash.
// Must match argon2-cffi's PasswordHasher(time_cost=3, memory_cost=65536,
// parallelism=2, hash_len=32, salt_len=16) from the Python build exactly,
// or existing accounts (password_hash column) won't verify.
struct LoginHashParams {
    uint32_t timeCost = 3;
    uint32_t memoryCostKiB = 65536;   // 64 MiB
    uint32_t parallelism = 2;
    uint32_t hashLen = 32;
    uint32_t saltLen = 16;
};

// Argon2id parameters for deriving the Key-Encryption-Key (KEK) that wraps
// the random 256-bit Vault Key. Mirrors Python's CURRENT_KDF_PARAMS.
// Bump "version" (and any field) to trigger the same transparent re-wrap
// behavior login() already implements below.
struct KekParams {
    int version = 1;
    uint32_t timeCost = 4;
    uint32_t memoryCostKiB = 131072;  // 128 MiB
    uint32_t parallelism = 4;
};

// A logged-in session. The Vault Key is the only long-lived secret kept in
// memory; it never touches disk and is zeroed out on logout().
struct Session {
    int userId = 0;
    QString username;
    QByteArray vaultKey;   // 32 raw bytes, zeroed in Backend::logout()
};

class Backend : public QObject {
    Q_OBJECT

public:
    explicit Backend(Database *db, QObject *parent = nullptr);
    ~Backend() override;

public slots:
    // ---- Auth: called from login.html, result delivered via signals below ----
    void login(const QString &username, const QString &password);
    void createAccount(const QString &username, const QString &password);

    // ---- Session / vault: called from dashboard.html, result returned directly
    //      (QWebChannel auto-generates a JS callback for any Q_INVOKABLE / slot
    //      with a return value - matches the Python `result=str` convention). ----
    QString getCurrentUser();
    bool logout();
    QString getVaultItems();
    QString addVaultItem(const QString &name, const QString &url,
                          const QString &username, const QString &password);
    QString revealPassword(int itemId);
    QString deleteVaultItem(int itemId);

signals:
    void loginResult(bool success, const QString &message);
    void createAccountResult(bool success, const QString &message);

private:
    Database *db_;
    std::unique_ptr<Session> session_;

    // ---------------- validation ----------------
    static std::optional<QString> validateUsername(QString &username);
    static std::optional<QString> validatePassword(const QString &password);

    // ---------------- Argon2id (login hash) ----------------
    QString hashPassword(const QString &password) const;
    bool verifyPassword(const QString &hash, const QString &password) const;

    // ---------------- Argon2id (KEK derivation) + AES-256-GCM (Vault Key wrap / item encryption) ----------------
    QByteArray deriveKek(const QString &password, const QByteArray &salt, const KekParams &params) const;
    static QString aesEncrypt(const QByteArray &key, const QByteArray &plaintext);
    static std::optional<QByteArray> aesDecrypt(const QByteArray &key, const QString &blobB64);

    static QString kekParamsToJson(const KekParams &params);
    static std::optional<KekParams> kekParamsFromJson(const QString &json);
    bool paramsNeedUpgrade(const QString &storedJson) const;

    // One-time upgrade path for any account still on the Python build's older
    // PBKDF2+Fernet scheme (kek_salt / encrypted_vault_key empty). Not expected
    // to be hit for accounts already migrated by the Python build, but kept for
    // safety - it will refuse (return nullopt) rather than guess.
    std::optional<QByteArray> migrateLegacyAccount(int userId, const QString &password,
                                                     const QString &kdfSaltB64);
};
