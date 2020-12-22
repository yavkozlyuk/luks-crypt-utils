#include "cipher.h"
#include "luksconstants.h"
#include "utils.h"
Cipher::Cipher()
{
    this->hd_enc = EVP_CIPHER_CTX_new();
    this->hd_dec = EVP_CIPHER_CTX_new();
}

Cipher::~Cipher()
{
    if (this->hd_enc) {
        EVP_CIPHER_CTX_free(this->hd_enc);
        this->hd_enc = NULL;
    }
    if (this->hd_dec) {
        EVP_CIPHER_CTX_free(this->hd_dec);
        this->hd_dec = NULL;
    }
}
int Cipher::init(const char *name, const char *mode, const unsigned char *key, size_t keyLength)
{
    int r;
    char cipherName[256];
    const EVP_CIPHER *type;
    int key_bits;

    key_bits = keyLength * 8;
    if (!strcmp(mode, "xts"))
        key_bits /= 2;
    if (!strcmp(name, "kuznyechik")) {
        r = snprintf(cipherName, sizeof(cipherName), "%s-%s", "grasshopper", mode);
    } else {
        r = snprintf(cipherName, sizeof(cipherName), "%s-%d-%s", name, key_bits, mode);
    }
    if (r < 0 || r >= (int) sizeof(cipherName))
        return -EINVAL;

    OpenSSL_add_all_ciphers();
    type = EVP_get_cipherbyname(cipherName);
    if (!type) {
        printf("Can not get %s cipher [openssl-evp]", cipherName);
        return -ENOENT;
    }


    if (EVP_CIPHER_key_length(type) != (int) keyLength)
        return -EINVAL;

    this->ivLength = EVP_CIPHER_iv_length(type);

    if (!this->hd_enc || !this->hd_dec)
        return -EINVAL;

    if (EVP_EncryptInit_ex(this->hd_enc, type, NULL, key, NULL) != 1 || EVP_DecryptInit_ex(this->hd_dec, type, NULL, key, NULL) != 1) {
        return -EINVAL;
    }

    if (EVP_CIPHER_CTX_set_padding(this->hd_enc, 0) != 1 || EVP_CIPHER_CTX_set_padding(this->hd_dec, 0) != 1) {
        return -EINVAL;
    }
    return 0;
}


int Cipher::encrypt(const unsigned char *in, unsigned char *out, size_t length, const unsigned char *iv, size_t iv_length)
{
    int len;

    if (this->ivLength != iv_length)
        return -EINVAL;

    if (EVP_EncryptInit_ex(this->hd_enc, NULL, NULL, NULL, iv) != 1)
        return -EINVAL;

    if (EVP_EncryptUpdate(this->hd_enc, out, &len, in, length) != 1)
        return -EINVAL;

    if (EVP_EncryptFinal(this->hd_enc, out + len, &len) != 1)
        return -EINVAL;

    return 0;
}


int Cipher::decrypt(const unsigned char  *in, unsigned char * out, size_t length, const unsigned char *iv, size_t iv_length)
{
    int len;

    if (this->ivLength != iv_length)
        return -EINVAL;

    if (EVP_DecryptInit_ex(this->hd_dec, NULL, NULL, NULL, iv) != 1)
        return -EINVAL;

    if (EVP_DecryptUpdate(this->hd_dec, out, &len, in, length) != 1)
        return -EINVAL;

    if (EVP_DecryptFinal(this->hd_dec, out + len, &len) != 1)
        return -EINVAL;

    return 0;
}

const CipherAlgorithm *Cipher::_getAlg(const char *name, const char *mode)
{
    int i = 0;

    while (name && cipher_algs[i].name) {
        if (!strcasecmp(name, cipher_algs[i].name))
            if (!mode || !cipher_algs[i].mode || !strncasecmp(mode, cipher_algs[i].mode, strlen(cipher_algs[i].mode)))
                return &cipher_algs[i];
        i++;
    }
    return NULL;
}

int Cipher::cipherIVSize(const char *name, const char *mode) {
    const struct CipherAlgorithm *ca = _getAlg(name, mode);

    if (!ca)
        return -EINVAL;

    if (mode && !strcasecmp(mode, "ecb"))
        return 0;

    return ca->blocksize;
}

int Cipher::sectorIVInit(struct SectorIV *ctx, const char *cipherName, const char *mode_name, const char *iv_name, const unsigned char * key, size_t keyLength, size_t sector_size) {
    int r;

    memset(ctx, 0, sizeof(*ctx));

    ctx->ivSize = Cipher::cipherIVSize(cipherName, mode_name);
    if (ctx->ivSize < 0 || (strcmp(mode_name, "ecb") && ctx->ivSize < 8))
        return -ENOENT;

    if (!strcmp(cipherName, "cipher_null") || !strcmp(mode_name, "ecb")) {
        if (iv_name)
            return -EINVAL;
        ctx->type = IV_NONE;
        ctx->ivSize = 0;
        return 0;
    } else if (!iv_name) {
        return -EINVAL;
    } else if (!strcasecmp(iv_name, "null")) {
        ctx->type = IV_NULL;
    } else if (!strcasecmp(iv_name, "plain64")) {
        ctx->type = IV_PLAIN64;
    } else if (!strcasecmp(iv_name, "plain64be")) {
        ctx->type = IV_PLAIN64BE;
    } else if (!strcasecmp(iv_name, "plain")) {
        ctx->type = IV_PLAIN;
    } else if (!strncasecmp(iv_name, "essiv:", 6)) {
        HashFunction *h = new HashFunction();
        const char *hash_name = strchr(iv_name, ':');
        int hash_size;
        unsigned char tmp[256];
        int r;

        if (!hash_name) {
            delete h;
            return -EINVAL;
        }

        hash_size = HashFunction::hashSize(++hash_name);
        if (hash_size < 0) {
            delete h;
            return -ENOENT;
        }
        if ((unsigned) hash_size > sizeof(tmp)) {
            delete h;
            return -EINVAL;
        }
        if (h->init(hash_name)) {
            delete h;
            return -EINVAL;

        }
        r = h->write(key, keyLength);
        if (r) {
            delete h;
            return r;
        }

        r = h->final(tmp, hash_size);
        if (r) {
            backendMemzero(tmp, sizeof(tmp));
            delete h;
            return r;
        }

        r = ctx->cipher->init(cipherName, "ecb", tmp, hash_size);
        backendMemzero(tmp, sizeof(tmp));
        if (r) {
            delete h;
            return r;
        }
        ctx->type = IV_ESSIV;
    } else if (!strncasecmp(iv_name, "benbi", 5)) {
        int log = Utils::intLog2(ctx->ivSize);
        if (log > SECTOR_SHIFT) {
            return -EINVAL;
        }
        ctx->type = IV_BENBI;
        ctx->shift = SECTOR_SHIFT - log;
    } else if (!strncasecmp(iv_name, "eboiv", 5)) {
        r = ctx->cipher->init(cipherName, "ecb", key, keyLength);
        if (r) {
            return r;
        }

        ctx->type = IV_EBOIV;
        ctx->shift = Utils::intLog2(sector_size);
    } else {
        return -ENOENT;
    }
    ctx->iv = (unsigned char *)malloc(ctx->ivSize);
    if (!ctx->iv) {
        return -ENOMEM;
    }
    return 0;
}

int Cipher::sectorIVGenerate(struct SectorIV *ctx, uint64_t sector)
{
    uint64_t val;

    switch (ctx->type) {
    case IV_NONE:
        break;
    case IV_NULL:
        memset(ctx->iv, 0, ctx->ivSize);
        break;
    case IV_PLAIN:
        memset(ctx->iv, 0, ctx->ivSize);
        *(uint32_t*) ctx->iv = cpu_to_le32(sector & 0xffffffff);
        break;
    case IV_PLAIN64:
        memset(ctx->iv, 0, ctx->ivSize);
        *(uint64_t*) ctx->iv = cpu_to_le64(sector);
        break;
    case IV_PLAIN64BE:
        memset(ctx->iv, 0, ctx->ivSize);
        *(uint64_t*) &ctx->iv[ctx->ivSize - sizeof(uint64_t)] = cpu_to_be64(sector);
        break;
    case IV_ESSIV:
        memset(ctx->iv, 0, ctx->ivSize);
        *(uint64_t*) ctx->iv = cpu_to_le64(sector);
        return ctx->cipher->encrypt(ctx->iv, ctx->iv, ctx->ivSize,NULL, 0);
        break;
    case IV_BENBI:
        memset(ctx->iv, 0, ctx->ivSize);
        val = cpu_to_be64((sector << ctx->shift) + 1);
        memcpy(ctx->iv + ctx->ivSize - sizeof(val), &val, sizeof(val));
        break;
    case IV_EBOIV:
        memset(ctx->iv, 0, ctx->ivSize);
        *(uint64_t*) ctx->iv = cpu_to_le64(sector << ctx->shift);
        return ctx->cipher->encrypt(ctx->iv, ctx->iv, ctx->ivSize,
                                    NULL, 0);
        break;
    default:
        return -EINVAL;
    }

    return 0;
}

void Cipher::sectorIVDestroy(struct SectorIV * ctx)
{
    if (ctx->type == SectorIVType::IV_ESSIV || ctx->type == SectorIVType::IV_EBOIV)
        ctx->cipher.reset();

    if (ctx->iv) {
        Utils::safeMemzero(ctx->iv, ctx->ivSize);
        free(ctx->iv);
    }

    Utils::safeMemzero(ctx,sizeof(*ctx));
}

