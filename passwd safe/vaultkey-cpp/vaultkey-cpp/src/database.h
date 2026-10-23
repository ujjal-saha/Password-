#pragma once

#include <QString>
#include <QList>
#include <sqlite3.h>
#include <optional>

// One user row, as read from the db. Mirrors Python's UserDatabase.get_user()
// tuple: (id, password_hash, kdf_salt, kek_salt, encrypted_vault_key, kdf_params)
struct UserRow {
    int id = 0;
    QString passwordHash;
    QString kdfSalt;            // legacy PBKDF2 salt - empty string on migrated accounts
    QString kekSalt;
    QString encryptedVaultKey;
    QString kdfParamsJson;
};

struct VaultItemRow {
    int id = 0;
    QString name;
    QString url;
    QString username;
    QString createdAt;
};

// C++ port of UserDatabase (main.py). Same schema, same table names, so the
// existing vault.db from the Python build is read/written as-is.
class Database {
public:
    explicit Database(const QString &path);
    ~Database();

    bool isOpen() const { return db_ != nullptr; }

    // ---------------- users ----------------
    bool usernameExists(const QString &username);
    bool createUser(const QString &username, const QString &passwordHash,
                     const QString &kekSaltB64, const QString &encryptedVaultKeyB64,
                     const QString &kdfParamsJson);
    std::optional<UserRow> getUser(const QString &username);
    void updatePasswordHash(const QString &username, const QString &newHash);
    void updateVaultKeyAndParams(int userId, const QString &kekSaltB64,
                                  const QString &encryptedVaultKeyB64,
                                  const QString &kdfParamsJson);

    // ---------------- vault items ----------------
    int addVaultItem(int userId, const QString &name, const QString &url,
                      const QString &username, const QString &encryptedPassword);
    QList<VaultItemRow> getVaultItems(int userId);
    std::optional<QString> getEncryptedPassword(int itemId, int userId);
    bool deleteVaultItem(int itemId, int userId);

private:
    sqlite3 *db_ = nullptr;
    void initSchema();
    void migrateSchema();
    bool columnExists(const QString &table, const QString &column);
};
