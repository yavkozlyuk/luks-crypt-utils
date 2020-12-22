#pragma once
#ifndef CIPHER_H
#define CIPHER_H

#include <openssl/evp.h>
# include <openssl/ossl_typ.h>
#include <memory>
#include <string.h>
#include "bitops.h"
#include "hashfunction.h"
struct CipherAlgorithm {
    const char *name;
    const char *mode;
    int blocksize;
    bool wrapped_key;
};
/* FIXME: Getting block size should be dynamic from cipher backend. */
static const struct CipherAlgorithm cipher_algs[] = { { "cipher_null", NULL, 16, false },
{"kuznyechik", NULL, 64, false},
{ "aes", NULL, 16, false },
{ "serpent", NULL, 16, false },
{ "twofish", NULL, 16, false },
{ "anubis", NULL, 16, false },
{ "blowfish", NULL, 8, false },
{ "camellia", NULL, 16, false },
{ "cast5", NULL, 8, false },
{ "cast6", NULL, 16, false },
{ "des", NULL, 8, false },
{ "des3_ede", NULL, 8, false },
{ "khazad", NULL, 8, false },
{ "seed", NULL, 16, false },
{ "tea",NULL, 8, false },
{ "xtea", NULL, 8, false },
{ "paes", NULL, 16, true },
/* protected AES, s390 wrapped key scheme */
/*{ "xchacha12,aes", "adiantum", 32, false },*/
{ "xchacha20,aes", "adiantum", 32, false },
{ "sm4", NULL, 16, false },
{ NULL, NULL, 0, false }};
enum SectorIVType {
    IV_NONE, IV_NULL, IV_PLAIN, IV_PLAIN64, IV_ESSIV, IV_BENBI, IV_PLAIN64BE, IV_EBOIV
};

class Cipher
{
public:
    Cipher();
    virtual ~Cipher();
    int init(const char *name, const char *mode, const unsigned char *key, size_t keyLength);
    int encrypt(const unsigned char *in, unsigned char *out, size_t length, const unsigned char *iv, size_t iv_length);
    int decrypt(const unsigned char*, unsigned char*, size_t, const unsigned char*, size_t);
    static const struct CipherAlgorithm *_getAlg(const char *name, const char *mode);
    static int cipherIVSize(const char *name, const char *mode);
    static int sectorIVInit(struct SectorIV *ctx, const char *cipherName, const char *mode_name, const char *iv_name, const unsigned char * key, size_t keyLength, size_t sector_size);
    static int sectorIVGenerate(struct SectorIV*, uint64_t);
    static void sectorIVDestroy(struct SectorIV*);
private:
    EVP_CIPHER_CTX* hd_enc;
    EVP_CIPHER_CTX* hd_dec;
    size_t ivLength;
};
struct SectorIV {
    SectorIVType type;
    int ivSize;
    unsigned char *iv;
    std::shared_ptr<Cipher> cipher;
    int shift;
};
#endif // CIPHER_H
