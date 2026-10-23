#include "backend.h"

#include <QJsonDocument>
#include <QJsonObject>
#include <QJsonArray>
#include <QRandomGenerator>

#include <argon2.h>
#include <openssl/rand.h>
#include <openssl/evp.h>

#include <cstring>

namespace {

constexpr int GCM_NONCE_LEN = 12;
constexpr int GCM_TAG_LEN = 16;
constexpr int VAULT_KEY_LEN = 32;
constexpr int KEK_SALT_LEN = 16;

QByteArray randomBytes(int n) {
    QByteArray buf(n, 0);
    RAND_bytes(reinterpret_cast<unsigned char *>(buf.data()), n);
    return buf;
}

QString jsonMessage(bool success, const QString &message) {
    QJsonObject obj{{"success", success}, {"message", message}};
    return QString::fromUtf8(QJsonDocument(obj).toJson(QJsonDocument::Compact));
}

} // namespace

Backend::Backend(Database *db, QObject *parent) : QObject(parent), db_(db) {}

Backend::~Backend() {
    // Best-effort zero of the Vault Key on shutdown, same intent as the
    // Python build's bytearray overwrite in logout().
    if (session_) {
        session_->vaultKey.fill(0);
    }
}

// ============================================================
// Validation
// ============================================================
std::optional<QString> Backend::validateUsername(QString &username) {
    username = username.trimmed();
    if (username.isEmpty()) return "Username cannot be empty.";
    if (username.length() < 3) return "Username must be at least 3 characters.";
    if (username.length() > 32) return "Username must be 32 characters or fewer.";
    return std::nullopt;
}

std::optional<QString> Backend::validatePassword(const QString &password) {
    if (password.isEmpty()) return "Password cannot be empty.";
    if (password.length() < 8) return "Password must be at least 8 characters.";
    return std::nullopt;
}

// ============================================================
// Argon2id - login password hash (matches argon2-cffi PasswordHasher
// defaults used by the Python build: t=3, m=65536 KiB, p=2, hashLen=32, saltLen=16)
// ============================================================
QString Backend::hashPassword(const QString &password) const {
    LoginHashParams p;
    QByteArray salt = randomBytes(p.saltLen);
    QByteArray pwBytes = password.toUtf8();

    size_t encodedLen = argon2_encodedlen(p.timeCost, p.memoryCostKiB, p.parallelism,
                                           p.saltLen, p.hashLen, Argon2_id);
    QByteArray encoded(static_cast<int>(encodedLen), 0);

    int rc = argon2id_hash_encoded(
        p.timeCost, p.memoryCostKiB, p.parallelism,
        pwBytes.constData(), pwBytes.size(),
        salt.constData(), salt.size(),
        p.hashLen,
        encoded.data(), encoded.size());

    if (rc != ARGON2_OK) return QString();
    // encoded is a NUL-terminated C string inside the buffer.
    return QString::fromUtf8(encoded.constData());
}

bool Backend::verifyPassword(const QString &hash, const QString &password) const {
    QByteArray hashBytes = hash.toUtf8();
    QByteArray pwBytes = password.toUtf8();
    int rc = argon2id_verify(hashBytes.constData(), pwBytes.constData(), pwBytes.size());
    return rc == ARGON2_OK;
}

// ============================================================
// Argon2id - Key-Encryption-Key derivation (matches Python's _derive_kek /
// CURRENT_KDF_PARAMS: t=4, m=131072 KiB, p=4, 32-byte raw output)
// ============================================================
QByteArray Backend::deriveKek(const QString &password, const QByteArray &salt,
                               const KekParams &params) const {
    QByteArray pwBytes = password.toUtf8();
    QByteArray out(VAULT_KEY_LEN, 0);

    int rc = argon2id_hash_raw(
        params.timeCost, params.memoryCostKiB, params.parallelism,
        pwBytes.constData(), pwBytes.size(),
        salt.constData(), salt.size(),
        out.data(), out.size());

    if (rc != ARGON2_OK) return QByteArray();
    return out;
}

QString Backend::kekParamsToJson(const KekParams &params) {
    QJsonObject obj{
        {"version", params.version},
        {"type", "argon2id"},
        {"time_cost", static_cast<int>(params.timeCost)},
        {"memory_cost", static_cast<int>(params.memoryCostKiB)},
        {"parallelism", static_cast<int>(params.parallelism)},
    };
    return QString::fromUtf8(QJsonDocument(obj).toJson(QJsonDocument::Compact));
}

std::optional<KekParams> Backend::kekParamsFromJson(const QString &json) {
    if (json.isEmpty()) return std::nullopt;
    QJsonDocument doc = QJsonDocument::fromJson(json.toUtf8());
    if (!doc.isObject()) return std::nullopt;
    QJsonObject obj = doc.object();

    KekParams params;
    params.version = obj.value("version").toInt(0);
    params.timeCost = static_cast<uint32_t>(obj.value("time_cost").toInt());
    params.memoryCostKiB = static_cast<uint32_t>(obj.value("memory_cost").toInt());
    params.parallelism = static_cast<uint32_t>(obj.value("parallelism").toInt());
    return params;
}

bool Backend::paramsNeedUpgrade(const QString &storedJson) const {
    auto stored = kekParamsFromJson(storedJson);
    if (!stored) return true;
    KekParams current;
    return stored->version < current.version;
}

// ============================================================
// AES-256-GCM. Layout: base64( nonce[12] || ciphertext || tag[16] ) -
// identical to what Python's `cryptography` AESGCM produces, so blobs
// written by either build are readable by the other.
// ============================================================
QString Backend::aesEncrypt(const QByteArray &key, const QByteArray &plaintext) {
    QByteArray nonce = randomBytes(GCM_NONCE_LEN);
    QByteArray ciphertext(plaintext.size() + EVP_MAX_BLOCK_LENGTH, 0);
    QByteArray tag(GCM_TAG_LEN, 0);
    int len = 0, ciphertextLen = 0;

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr);
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, GCM_NONCE_LEN, nullptr);
    EVP_EncryptInit_ex(ctx, nullptr, nullptr,
                        reinterpret_cast<const unsigned char *>(key.constData()),
                        reinterpret_cast<const unsigned char *>(nonce.constData()));

    EVP_EncryptUpdate(ctx, reinterpret_cast<unsigned char *>(ciphertext.data()), &len,
                       reinterpret_cast<const unsigned char *>(plaintext.constData()), plaintext.size());
    ciphertextLen = len;

    EVP_EncryptFinal_ex(ctx, reinterpret_cast<unsigned char *>(ciphertext.data()) + len, &len);
    ciphertextLen += len;

    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, GCM_TAG_LEN,
                         reinterpret_cast<unsigned char *>(tag.data()));
    EVP_CIPHER_CTX_free(ctx);

    QByteArray blob;
    blob.append(nonce);
    blob.append(ciphertext.left(ciphertextLen));
    blob.append(tag);
    return QString::fromLatin1(blob.toBase64());
}

std::optional<QByteArray> Backend::aesDecrypt(const QByteArray &key, const QString &blobB64) {
    QByteArray blob = QByteArray::fromBase64(blobB64.toLatin1());
    if (blob.size() < GCM_NONCE_LEN + GCM_TAG_LEN) return std::nullopt;

    QByteArray nonce = blob.left(GCM_NONCE_LEN);
    QByteArray tag = blob.right(GCM_TAG_LEN);
    QByteArray ciphertext = blob.mid(GCM_NONCE_LEN, blob.size() - GCM_NONCE_LEN - GCM_TAG_LEN);
    QByteArray plaintext(ciphertext.size() + EVP_MAX_BLOCK_LENGTH, 0);
    int len = 0, plaintextLen = 0;

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr);
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, GCM_NONCE_LEN, nullptr);
    EVP_DecryptInit_ex(ctx, nullptr, nullptr,
                        reinterpret_cast<const unsigned char *>(key.constData()),
                        reinterpret_cast<const unsigned char *>(nonce.constData()));

    EVP_DecryptUpdate(ctx, reinterpret_cast<unsigned char *>(plaintext.data()), &len,
                       reinterpret_cast<const unsigned char *>(ciphertext.constData()), ciphertext.size());
    plaintextLen = len;

    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, GCM_TAG_LEN,
                         const_cast<char *>(tag.constData()));

    int ok = EVP_DecryptFinal_ex(ctx, reinterpret_cast<unsigned char *>(plaintext.data()) + len, &len);
    EVP_CIPHER_CTX_free(ctx);

    if (ok <= 0) return std::nullopt;  // tag mismatch - tampered or wrong key
    plaintextLen += len;
    return plaintext.left(plaintextLen);
}

// ============================================================
// Legacy (pre-Vault-Key) account migration.
//
// The Python build's very first release derived vault encryption keys
// straight from the password via PBKDF2 + Fernet, before the Argon2id-KEK +
// AES-256-GCM scheme existed. Any account still in that state has an empty
// kek_salt/encrypted_vault_key and a non-empty legacy kdf_salt.
//
// Re-implementing Fernet (AES-128-CBC + HMAC-SHA256, versioned token format)
// here just to read that old format is a lot of surface area for a path
// that, as of this build, no real account needs - the one existing account
// (ujjal) is already on the new scheme. So this intentionally refuses rather
// than guess. If you ever hit this in practice: log in once with the Python
// build first (it still has the Fernet migration code) to upgrade the
// account, then switch back to this build.
// ============================================================
std::optional<QByteArray> Backend::migrateLegacyAccount(int /*userId*/, const QString & /*password*/,
                                                           const QString & /*kdfSaltB64*/) {
    return std::nullopt;
}

// ============================================================
// Slots - AUTH
// ============================================================
void Backend::login(const QString &usernameIn, const QString &password) {
    QString username = usernameIn;
    if (auto err = validateUsername(username)) {
        emit loginResult(false, *err);
        return;
    }

    auto row = db_->getUser(username);
    if (!row) {
        emit loginResult(false, "Invalid username or password.");
        return;
    }

    if (!verifyPassword(row->passwordHash, password)) {
        emit loginResult(false, "Invalid username or password.");
        return;
    }

    QByteArray vaultKey;

    if (!row->kekSalt.isEmpty() && !row->encryptedVaultKey.isEmpty()) {
        auto storedParams = kekParamsFromJson(row->kdfParamsJson);
        KekParams paramsToUse = storedParams.value_or(KekParams{});

        QByteArray kekSalt = QByteArray::fromBase64(row->kekSalt.toLatin1());
        QByteArray kek = deriveKek(password, kekSalt, paramsToUse);

        auto decrypted = aesDecrypt(kek, row->encryptedVaultKey);
        if (!decrypted) {
            emit loginResult(false, "Account data is corrupted. Contact support.");
            return;
        }
        vaultKey = *decrypted;

        if (paramsNeedUpgrade(row->kdfParamsJson)) {
            KekParams current;
            QByteArray newKekSalt = randomBytes(KEK_SALT_LEN);
            QByteArray newKek = deriveKek(password, newKekSalt, current);
            QString newWrapped = aesEncrypt(newKek, vaultKey);
            db_->updateVaultKeyAndParams(
                row->id,
                QString::fromLatin1(newKekSalt.toBase64()),
                newWrapped,
                kekParamsToJson(current));
        }
    } else {
        auto migrated = migrateLegacyAccount(row->id, password, row->kdfSalt);
        if (!migrated) {
            emit loginResult(false,
                "This account needs a one-time upgrade. Please log in with the "
                "previous version of VaultKey once, then try again here.");
            return;
        }
        vaultKey = *migrated;
    }

    session_ = std::make_unique<Session>();
    session_->userId = row->id;
    session_->username = username;
    session_->vaultKey = vaultKey;

    emit loginResult(true, "OK");
}

void Backend::createAccount(const QString &usernameIn, const QString &password) {
    QString username = usernameIn;
    if (auto err = validateUsername(username)) {
        emit createAccountResult(false, *err);
        return;
    }
    if (auto err = validatePassword(password)) {
        emit createAccountResult(false, *err);
        return;
    }
    if (db_->usernameExists(username)) {
        emit createAccountResult(false, "That username is already taken.");
        return;
    }

    QString passwordHash = hashPassword(password);
    if (passwordHash.isEmpty()) {
        emit createAccountResult(false, "Internal error hashing password.");
        return;
    }

    KekParams current;
    QByteArray kekSalt = randomBytes(KEK_SALT_LEN);
    QByteArray kek = deriveKek(password, kekSalt, current);
    QByteArray vaultKey = randomBytes(VAULT_KEY_LEN);
    QString encryptedVaultKey = aesEncrypt(kek, vaultKey);

    bool ok = db_->createUser(
        username, passwordHash,
        QString::fromLatin1(kekSalt.toBase64()),
        encryptedVaultKey,
        kekParamsToJson(current));

    if (!ok) {
        emit createAccountResult(false, "That username is already taken.");
        return;
    }

    emit createAccountResult(true, "Account created.");
}

// ============================================================
// Slots - SESSION
// ============================================================
QString Backend::getCurrentUser() {
    QJsonObject obj;
    if (!session_) {
        obj["loggedIn"] = false;
    } else {
        obj["loggedIn"] = true;
        obj["username"] = session_->username;
    }
    return QString::fromUtf8(QJsonDocument(obj).toJson(QJsonDocument::Compact));
}

bool Backend::logout() {
    if (session_) {
        session_->vaultKey.fill(0);  // best-effort zero before dropping the buffer
        session_.reset();
    }
    return true;
}

// ============================================================
// Slots - VAULT
// ============================================================
QString Backend::getVaultItems() {
    if (!session_) return jsonMessage(false, "Not logged in.");

    auto items = db_->getVaultItems(session_->userId);
    QJsonArray arr;
    for (const auto &item : items) {
        QJsonObject obj{
            {"id", item.id},
            {"name", item.name},
            {"url", item.url},
            {"username", item.username},
            {"createdAt", item.createdAt},
        };
        arr.append(obj);
    }
    QJsonObject result{{"success", true}, {"items", arr}};
    return QString::fromUtf8(QJsonDocument(result).toJson(QJsonDocument::Compact));
}

QString Backend::addVaultItem(const QString &name, const QString &url,
                               const QString &username, const QString &password) {
    if (!session_) return jsonMessage(false, "Not logged in.");

    QString trimmedName = name.trimmed();
    if (trimmedName.isEmpty()) return jsonMessage(false, "Item name cannot be empty.");
    if (password.isEmpty()) return jsonMessage(false, "Password cannot be empty.");

    QString encrypted = aesEncrypt(session_->vaultKey, password.toUtf8());
    int newId = db_->addVaultItem(session_->userId, trimmedName, url.trimmed(),
                                   username.trimmed(), encrypted);

    QJsonObject obj{{"success", true}, {"message", "Saved."}, {"id", newId}};
    return QString::fromUtf8(QJsonDocument(obj).toJson(QJsonDocument::Compact));
}

QString Backend::revealPassword(int itemId) {
    if (!session_) return jsonMessage(false, "Not logged in.");

    auto encrypted = db_->getEncryptedPassword(itemId, session_->userId);
    if (!encrypted) return jsonMessage(false, "Item not found.");

    auto plaintext = aesDecrypt(session_->vaultKey, *encrypted);
    if (!plaintext) return jsonMessage(false, "Could not decrypt this item.");

    QJsonObject obj{{"success", true}, {"password", QString::fromUtf8(*plaintext)}};
    return QString::fromUtf8(QJsonDocument(obj).toJson(QJsonDocument::Compact));
}

QString Backend::deleteVaultItem(int itemId) {
    if (!session_) return jsonMessage(false, "Not logged in.");

    if (!db_->deleteVaultItem(itemId, session_->userId))
        return jsonMessage(false, "Item not found.");

    return jsonMessage(true, "Deleted.");
}
