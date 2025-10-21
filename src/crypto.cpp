#include "crypto.h"

namespace {

    // 打开/关闭 Base64 的换行（避免换行导致不一致）
    inline void set_base64_no_nl(BIO* b64) {
        // OpenSSL 1.1+ 生效；旧版本忽略此标志也无害
        BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
    }

} // anonymous namespace

RSA* crypto::createPrivateRSA(std::string key) {
    RSA* rsa = nullptr;
    BIO* keybio = BIO_new_mem_buf((void*)key.c_str(), -1);
    if (!keybio) return nullptr;
    rsa = PEM_read_bio_RSAPrivateKey(keybio, nullptr, nullptr, nullptr);
    BIO_free(keybio);
    return rsa;
}

RSA* crypto::createPublicRSA(std::string key) {
    RSA* rsa = nullptr;
    BIO* keybio = BIO_new_mem_buf((void*)key.c_str(), -1);
    if (!keybio) return nullptr;
    // 与 PEM_write_bio_RSA_PUBKEY 配对（SubjectPublicKeyInfo）
    rsa = PEM_read_bio_RSA_PUBKEY(keybio, nullptr, nullptr, nullptr);
    BIO_free(keybio);
    return rsa;
}

bool crypto::RSASign(RSA* rsa,
    const unsigned char* Msg,
    size_t MsgLen,
    unsigned char** EncMsg,
    size_t* MsgLenEnc) {
    if (!rsa || !Msg || !EncMsg || !MsgLenEnc) return false;

    EVP_MD_CTX* m_RSASignCtx = EVP_MD_CTX_create();
    if (!m_RSASignCtx) return false;

    EVP_PKEY* priKey = EVP_PKEY_new();
    if (!priKey) { EVP_MD_CTX_free(m_RSASignCtx); return false; }

    // 复制引用（拥有者为 EVP_PKEY）
    if (EVP_PKEY_set1_RSA(priKey, rsa) != 1) {
        EVP_PKEY_free(priKey);
        EVP_MD_CTX_free(m_RSASignCtx);
        return false;
    }

    bool ok = true;
    if (EVP_DigestSignInit(m_RSASignCtx, nullptr, EVP_sha256(), nullptr, priKey) <= 0) ok = false;
    if (ok && EVP_DigestSignUpdate(m_RSASignCtx, Msg, MsgLen) <= 0) ok = false;
    if (ok && EVP_DigestSignFinal(m_RSASignCtx, nullptr, MsgLenEnc) <= 0) ok = false;

    if (ok) {
        *EncMsg = (unsigned char*)malloc(*MsgLenEnc);
        if (!*EncMsg) ok = false;
    }

    if (ok) {
        if (EVP_DigestSignFinal(m_RSASignCtx, *EncMsg, MsgLenEnc) <= 0) ok = false;
    }

    EVP_PKEY_free(priKey);
    EVP_MD_CTX_free(m_RSASignCtx);
    return ok;
}

bool crypto::RSAVerifySignature(RSA* rsa,
    unsigned char* Sig,
    size_t SigLen,
    const char* Msg,
    size_t MsgLen,
    bool* Authentic) {
    if (Authentic) *Authentic = false;
    if (!rsa || !Sig || !Msg || !Authentic) return false;

    EVP_PKEY* pubKey = EVP_PKEY_new();
    if (!pubKey) return false;

    if (EVP_PKEY_set1_RSA(pubKey, rsa) != 1) {
        EVP_PKEY_free(pubKey);
        return false;
    }

    EVP_MD_CTX* m_RSAVerifyCtx = EVP_MD_CTX_create();
    if (!m_RSAVerifyCtx) {
        EVP_PKEY_free(pubKey);
        return false;
    }

    bool ok = true;
    if (EVP_DigestVerifyInit(m_RSAVerifyCtx, nullptr, EVP_sha256(), nullptr, pubKey) <= 0) ok = false;
    if (ok && EVP_DigestVerifyUpdate(m_RSAVerifyCtx, Msg, MsgLen) <= 0) ok = false;

    if (ok) {
        int auth = EVP_DigestVerifyFinal(m_RSAVerifyCtx, Sig, SigLen);
        if (auth == 1) { *Authentic = true; ok = true; }
        else if (auth == 0) { *Authentic = false; ok = true; }
        else { *Authentic = false; ok = false; }
    }

    EVP_MD_CTX_free(m_RSAVerifyCtx);
    EVP_PKEY_free(pubKey);
    return ok;
}

void crypto::Base64Encode(const unsigned char* buffer,
    size_t length,
    char** base64Text) {
    if (!buffer || !base64Text) return;

    BIO* b64 = BIO_new(BIO_f_base64());
    BIO* bio = BIO_new(BIO_s_mem());
    if (!b64 || !bio) {
        if (b64) BIO_free(b64);
        if (bio) BIO_free(bio);
        *base64Text = nullptr;
        return;
    }

    set_base64_no_nl(b64); // ✅ 不插入换行
    bio = BIO_push(b64, bio);

    BIO_write(bio, buffer, (int)length);
    BIO_flush(bio);

    BUF_MEM* bufferPtr = nullptr;
    BIO_get_mem_ptr(bio, &bufferPtr);
    if (!bufferPtr || !bufferPtr->data || bufferPtr->length == 0) {
        BIO_free_all(bio);
        *base64Text = nullptr;
        return;
    }

    // ✅ 安全复制
    *base64Text = (char*)malloc(bufferPtr->length + 1);
    memcpy(*base64Text, bufferPtr->data, bufferPtr->length);
    (*base64Text)[bufferPtr->length] = '\0';

    BIO_free_all(bio);
}

size_t crypto::calcDecodeLength(const char* b64input) {
    if (!b64input) return 0;
    size_t len = strlen(b64input), padding = 0;
    if (len >= 2 && b64input[len - 1] == '=' && b64input[len - 2] == '=') padding = 2;
    else if (len >= 1 && b64input[len - 1] == '=') padding = 1;
    return (len * 3) / 4 - padding;
}

void crypto::Base64Decode(const char* b64message, unsigned char** buffer, size_t* length) {
    if (!b64message || !buffer || !length) return;

    int decodeLen = (int)calcDecodeLength(b64message);
    if (decodeLen <= 0) { *buffer = nullptr; *length = 0; return; }

    *buffer = (unsigned char*)malloc(decodeLen + 1);
    if (!*buffer) { *length = 0; return; }
    (*buffer)[decodeLen] = '\0';

    BIO* b64 = BIO_new(BIO_f_base64());
    BIO* bio = BIO_new_mem_buf(b64message, -1);
    if (!b64 || !bio) {
        if (b64) BIO_free(b64);
        if (bio) BIO_free(bio);
        free(*buffer); *buffer = nullptr; *length = 0;
        return;
    }

    set_base64_no_nl(b64); // ✅ 与编码一致
    bio = BIO_push(b64, bio);

    // ✅ 只读取“解码后的长度”，避免溢出
    int decoded = BIO_read(bio, *buffer, decodeLen);
    if (decoded < 0) decoded = 0;
    *length = (size_t)decoded;

    BIO_free_all(bio);
}

std::string crypto::signMessage(std::string privateKey, std::string plainText) {
    RSA* privateRSA = createPrivateRSA(privateKey);
    if (!privateRSA) return {};

    unsigned char* encMessage = nullptr;
    size_t encMessageLength = 0;

    bool ok = RSASign(privateRSA,
        (const unsigned char*)plainText.c_str(),
        plainText.size(),
        &encMessage,
        &encMessageLength);

    std::string out;
    if (ok && encMessage && encMessageLength > 0) {
        char* base64Text = nullptr;
        Base64Encode(encMessage, encMessageLength, &base64Text);
        if (base64Text) {
            out.assign(base64Text);
            free((void*)base64Text);
        }
    }

    if (encMessage) free(encMessage);
    RSA_free(privateRSA); // ✅ 释放

    return out;
}

bool crypto::verifySignature(std::string publicKey, std::string plainText, std::string signatureBase64) {
    RSA* publicRSA = createPublicRSA(publicKey);
    if (!publicRSA) return false;

    unsigned char* encMessage = nullptr;
    size_t encMessageLength = 0;
    Base64Decode(signatureBase64.c_str(), &encMessage, &encMessageLength);

    bool authentic = false;
    bool result = false;
    if (encMessage && encMessageLength > 0) {
        result = RSAVerifySignature(publicRSA,
            encMessage, encMessageLength,
            plainText.c_str(), plainText.size(),
            &authentic);
    }

    if (encMessage) free(encMessage);
    RSA_free(publicRSA); // ✅ 释放

    return result && authentic; // ✅ 逻辑与
}

const char* crypto::keyFromRSA(RSA* rsa, bool isPrivate) {
    if (!rsa) return nullptr;

    BIO* bio = BIO_new(BIO_s_mem());
    if (!bio) return nullptr;

    if (isPrivate) {
        PEM_write_bio_RSAPrivateKey(bio, rsa, nullptr, nullptr, 0, nullptr, nullptr);
    }
    else {
        // 导出 SubjectPublicKeyInfo: "-----BEGIN PUBLIC KEY-----"
        PEM_write_bio_RSA_PUBKEY(bio, rsa);
    }

    BUF_MEM* bufferPtr = nullptr;
    BIO_get_mem_ptr(bio, &bufferPtr);
    if (!bufferPtr || !bufferPtr->data || bufferPtr->length == 0) {
        BIO_free_all(bio);
        return nullptr;
    }

    // ✅ 安全复制整块内存（包含换行）
    char* key = (char*)malloc(bufferPtr->length + 1);
    memcpy(key, bufferPtr->data, bufferPtr->length);
    key[bufferPtr->length] = '\0';

    BIO_free_all(bio);
    return key;
}

void crypto::generate_key(std::string& public_key, std::string& private_key) {
    RSA* rsa = RSA_new();
    BIGNUM* bn = BN_new();
    BN_set_word(bn, RSA_F4);
    RSA_generate_key_ex(rsa, 1024, bn, nullptr);

    const char* pub = keyFromRSA(rsa, false);
    const char* pri = keyFromRSA(rsa, true);

    if (pub) { public_key.assign(pub);  free((void*)pub); }
    if (pri) { private_key.assign(pri); free((void*)pri); }

    BN_free(bn);
    RSA_free(rsa);
}

std::string crypto::sha256(std::string s) {
    char outputBuffer[65];
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256_CTX sha256;
    SHA256_Init(&sha256);
    SHA256_Update(&sha256, s.c_str(), s.size());
    SHA256_Final(hash, &sha256);
    for (int i = 0; i < SHA256_DIGEST_LENGTH; i++) {
        sprintf(outputBuffer + (i * 2), "%02x", hash[i]);
    }
    outputBuffer[64] = 0;
    return std::string{ outputBuffer };
}
