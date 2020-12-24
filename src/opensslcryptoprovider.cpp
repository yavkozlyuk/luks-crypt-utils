#include "opensslcryptoprovider.h"
#include <string.h>
#include <errno.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/hmac.h>
#include <openssl/rand.h>
#include <openssl/engine.h>
#include "utils.h"
#include "logger.h"
#define T(e) if (!(e)) {\
    ERR_print_errors_fp(stderr);\
    OpenSSLDie(__FILE__, __LINE__, #e);\
    }
static int providerInitialized = 0;

OpenSSLCryptoProvider::OpenSSLCryptoProvider() {

}

int OpenSSLCryptoProvider::initProvider() {
    if (providerInitialized)
        return 0;
    Logger::debug("Initializing openssl");
    setenv("OPENSSL_ENGINES", "/usr/lib/x86_64-linux-gnu/", 0);
    OPENSSL_add_all_algorithms_conf();
    ERR_load_crypto_strings();
    ENGINE *eng;
    T(eng = ENGINE_by_id("gost"));
    T(ENGINE_init(eng));
    T(ENGINE_set_default(eng, ENGINE_METHOD_ALL));
    OpenSSL_add_all_algorithms();

    providerInitialized = 1;
    return 0;
}

int OpenSSLCryptoProvider::pbdkf(const char *kdf, const char *hash, Key *password, const char *salt, size_t saltLength,
                                 Key *key, uint32_t iterations) {
    const EVP_MD *hash_id;

    if (!kdf)
        return -EINVAL;

    if (!strcmp(kdf, "pbkdf2")) {
        hash_id = EVP_get_digestbyname(hash);
        if (!hash_id)
            return -EINVAL;

        if (!PKCS5_PBKDF2_HMAC((const char *) password->getKey(), (int) password->getKeySize(), (unsigned char *) salt,
                               (int) saltLength, (int) iterations, hash_id, (int) key->getKeySize(),
                               (unsigned char *) key->getKey()))
            return -EINVAL;
        return 0;
    }

    return -EINVAL;
}

int OpenSSLCryptoProvider::verifyKey(const LuksPartitionHeader *hdr, Key *vk) {
    Key *testKey = new Key(LUKS_DIGEST_SIZE, NULL);
    int r = 0;

    if (pbdkf(CRYPT_KDF_PBKDF2, hdr->getHashSpec(), vk,
              hdr->getMkDigestSalt(), LUKS_SALT_SIZE, testKey,
              hdr->getMkDigestIter()) < 0) {
        r = -EINVAL;
        goto out;
    }

    if (memcmp(testKey->getKey(), hdr->getMkDigest(), LUKS_DIGEST_SIZE)) {
        r = -EPERM;
        goto out;
    }
    out:
    delete testKey;
    return r;

}

const char *OpenSSLCryptoProvider::getOpenSSLVersion() {
    return SSLeay_version(SSLEAY_VERSION);
}
