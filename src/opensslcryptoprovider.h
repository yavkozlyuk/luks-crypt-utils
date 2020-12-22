#pragma once
#ifndef OPENSSLCRYPTOPROVIDER_H
#define OPENSSLCRYPTOPROVIDER_H

#include  "key.h"
#include "lukspartitionheader.h"



class OpenSSLCryptoProvider {
public:
    OpenSSLCryptoProvider();
    static int initProvider();
    static int pbdkf(const char *kdf, const char *hash, Key* password,const char *salt, size_t salt_length,Key* key, uint32_t iterations);
    static int verifyKey(const LuksPartitionHeader *hdr,Key *vk);
    static const char *getOpenSSLVersion();
};

#endif // OPENSSLCRYPTOPROVIDER_H
