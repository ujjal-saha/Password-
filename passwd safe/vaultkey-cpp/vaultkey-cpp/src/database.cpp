#include "database.h"
#include <QDebug>

namespace {

// Small RAII wrapper so every prepared statement gets finalized even on
// early return / exception - avoids the manual sqlite3_finalize() at every
// call site that C code usually accumulates.
class Stmt {
public:
    Stmt(sqlite3 *db, const char *sql) {
        sqlite3_prepare_v2(db, sql, -1, &stmt_, nullptr);
    }
    ~Stmt() { if (stmt_) sqlite3_finalize(stmt_); }
    sqlite3_stmt *get() const { return stmt_; }
    operator sqlite3_stmt *() const { return stmt_; }

private:
    sqlite3_stmt *stmt_ = nullptr;
};

QString colText(sqlite3_stmt *stmt, int idx) {
    const unsigned char *text = sqlite3_column_text(stmt, idx);
    return text ? QString::fromUtf8(reinterpret_cast<const char *>(text)) : QString();
}

void bindText(sqlite3_stmt *stmt, int idx, const QString &value) {
    QByteArray bytes = value.toUtf8();
    sqlite3_bind_text(stmt, idx, bytes.constData(), bytes.size(), SQLITE_TRANSIENT);
}

} // namespace

Database::Database(const QString &path) {
    QByteArray pathBytes = path.toUtf8();
    if (sqlite3_open(pathBytes.constData(), &db_) != SQLITE_OK) {
        qWarning() << "Failed to open database:" << sqlite3_errmsg(db_);
        sqlite3_close(db_);
        db_ = nullptr;
        return;
    }
    sqlite3_exec(db_, "PRAGMA foreign_keys = ON", nullptr, nullptr, nullptr);
    sqlite3_exec(db_, "PRAGMA journal_mode = WAL", nullptr, nullptr, nullptr);
    sqlite3_exec(db_, "PRAGMA secure_delete = ON", nullptr, nullptr, nullptr);

    initSchema();
    migrateSchema();
}

Database::~Database() {
    if (db_) sqlite3_close(db_);
}

void Database::initSchema() {
    const char *usersSql = R"(
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
    )";
    const char *itemsSql = R"(
        CREATE TABLE IF NOT EXISTS vault_items (
            id                  INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id             INTEGER NOT NULL,
            name                TEXT NOT NULL,
            url                 TEXT,
            encrypted_password  TEXT NOT NULL,
            created_at          TEXT DEFAULT CURRENT_TIMESTAMP,
            username            TEXT,
            FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE
        )
    )";
    sqlite3_exec(db_, usersSql, nullptr, nullptr, nullptr);
    sqlite3_exec(db_, itemsSql, nullptr, nullptr, nullptr);
}

bool Database::columnExists(const QString &table, const QString &column) {
    Stmt stmt(db_, QString("PRAGMA table_info(%1)").arg(table).toUtf8().constData());
    while (sqlite3_step(stmt) == SQLITE_ROW) {
        if (colText(stmt, 1) == column) return true;
    }
    return false;
}

void Database::migrateSchema() {
    // Mirrors Python's _migrate_schema(): adds columns that post-date the
    // original layout, all nullable, so pre-existing rows are untouched
    // until they log in and get upgraded.
    if (!columnExists("users", "kek_salt"))
        sqlite3_exec(db_, "ALTER TABLE users ADD COLUMN kek_salt TEXT", nullptr, nullptr, nullptr);
    if (!columnExists("users", "encrypted_vault_key"))
        sqlite3_exec(db_, "ALTER TABLE users ADD COLUMN encrypted_vault_key TEXT", nullptr, nullptr, nullptr);
    if (!columnExists("users", "kdf_params"))
        sqlite3_exec(db_, "ALTER TABLE users ADD COLUMN kdf_params TEXT", nullptr, nullptr, nullptr);
    if (!columnExists("vault_items", "username"))
        sqlite3_exec(db_, "ALTER TABLE vault_items ADD COLUMN username TEXT", nullptr, nullptr, nullptr);
}

bool Database::usernameExists(const QString &username) {
    Stmt stmt(db_, "SELECT 1 FROM users WHERE username = ?");
    bindText(stmt, 1, username);
    return sqlite3_step(stmt) == SQLITE_ROW;
}

bool Database::createUser(const QString &username, const QString &passwordHash,
                           const QString &kekSaltB64, const QString &encryptedVaultKeyB64,
                           const QString &kdfParamsJson) {
    Stmt stmt(db_,
        "INSERT INTO users (username, password_hash, kdf_salt, kek_salt, encrypted_vault_key, kdf_params) "
        "VALUES (?, ?, '', ?, ?, ?)");
    bindText(stmt, 1, username);
    bindText(stmt, 2, passwordHash);
    bindText(stmt, 3, kekSaltB64);
    bindText(stmt, 4, encryptedVaultKeyB64);
    bindText(stmt, 5, kdfParamsJson);
    return sqlite3_step(stmt) == SQLITE_DONE;
}

std::optional<UserRow> Database::getUser(const QString &username) {
    Stmt stmt(db_,
        "SELECT id, password_hash, kdf_salt, kek_salt, encrypted_vault_key, kdf_params "
        "FROM users WHERE username = ?");
    bindText(stmt, 1, username);
    if (sqlite3_step(stmt) != SQLITE_ROW) return std::nullopt;

    UserRow row;
    row.id = sqlite3_column_int(stmt, 0);
    row.passwordHash = colText(stmt, 1);
    row.kdfSalt = colText(stmt, 2);
    row.kekSalt = colText(stmt, 3);
    row.encryptedVaultKey = colText(stmt, 4);
    row.kdfParamsJson = colText(stmt, 5);
    return row;
}

void Database::updatePasswordHash(const QString &username, const QString &newHash) {
    Stmt stmt(db_, "UPDATE users SET password_hash = ? WHERE username = ?");
    bindText(stmt, 1, newHash);
    bindText(stmt, 2, username);
    sqlite3_step(stmt);
}

void Database::updateVaultKeyAndParams(int userId, const QString &kekSaltB64,
                                        const QString &encryptedVaultKeyB64,
                                        const QString &kdfParamsJson) {
    Stmt stmt(db_,
        "UPDATE users SET kek_salt = ?, encrypted_vault_key = ?, kdf_params = ? WHERE id = ?");
    bindText(stmt, 1, kekSaltB64);
    bindText(stmt, 2, encryptedVaultKeyB64);
    bindText(stmt, 3, kdfParamsJson);
    sqlite3_bind_int(stmt, 4, userId);
    sqlite3_step(stmt);
}

int Database::addVaultItem(int userId, const QString &name, const QString &url,
                            const QString &username, const QString &encryptedPassword) {
    Stmt stmt(db_,
        "INSERT INTO vault_items (user_id, name, url, username, encrypted_password) "
        "VALUES (?, ?, ?, ?, ?)");
    sqlite3_bind_int(stmt, 1, userId);
    bindText(stmt, 2, name);
    bindText(stmt, 3, url);
    bindText(stmt, 4, username);
    bindText(stmt, 5, encryptedPassword);
    sqlite3_step(stmt);
    return static_cast<int>(sqlite3_last_insert_rowid(db_));
}

QList<VaultItemRow> Database::getVaultItems(int userId) {
    QList<VaultItemRow> items;
    Stmt stmt(db_,
        "SELECT id, name, url, username, created_at FROM vault_items "
        "WHERE user_id = ? ORDER BY created_at DESC");
    sqlite3_bind_int(stmt, 1, userId);
    while (sqlite3_step(stmt) == SQLITE_ROW) {
        VaultItemRow item;
        item.id = sqlite3_column_int(stmt, 0);
        item.name = colText(stmt, 1);
        item.url = colText(stmt, 2);
        item.username = colText(stmt, 3);
        item.createdAt = colText(stmt, 4);
        items.append(item);
    }
    return items;
}

std::optional<QString> Database::getEncryptedPassword(int itemId, int userId) {
    Stmt stmt(db_, "SELECT encrypted_password FROM vault_items WHERE id = ? AND user_id = ?");
    sqlite3_bind_int(stmt, 1, itemId);
    sqlite3_bind_int(stmt, 2, userId);
    if (sqlite3_step(stmt) != SQLITE_ROW) return std::nullopt;
    return colText(stmt, 0);
}

bool Database::deleteVaultItem(int itemId, int userId) {
    Stmt stmt(db_, "DELETE FROM vault_items WHERE id = ? AND user_id = ?");
    sqlite3_bind_int(stmt, 1, itemId);
    sqlite3_bind_int(stmt, 2, userId);
    sqlite3_step(stmt);
    return sqlite3_changes(db_) > 0;
}
