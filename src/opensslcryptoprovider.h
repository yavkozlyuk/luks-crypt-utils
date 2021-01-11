#pragma once
#ifndef OPENSSLCRYPTOPROVIDER_H
#define OPENSSLCRYPTOPROVIDER_H

#include <openssl/engine.h>
#include  "key.h"
#include "lukspartitionheader.h"


class OpenSSLCryptoProvider {
public:
    OpenSSLCryptoProvider();
    virtual ~OpenSSLCryptoProvider();

    static int initProvider();

    static void destroyProvider();

    static int pbdkf(const char *kdf, const char *hash, Key *password, const char *salt, size_t salt_length, Key *key,
                     uint32_t iterations);

    static int verifyKey(const LuksPartitionHeader *hdr, Key *vk);

    static const char *getOpenSSLVersion();

    static int listHashAlgorithms();

    static int listCipherAlgorithms();
};

#endif // OPENSSLCRYPTOPROVIDER_H
