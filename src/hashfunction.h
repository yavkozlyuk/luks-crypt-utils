#pragma once
#ifndef HASHFUNCTION_H
#define HASHFUNCTION_H

#include <openssl/evp.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <stddef.h>

class HashFunction {
public:
    HashFunction();

    virtual ~HashFunction();

    int init(const char *name);

    int write(const unsigned char *buffer, size_t length);

    int final(unsigned char *buffer, size_t length);

    static int hashSize(const char *name);

    static int hashRestart(HashFunction *hashFunction);

private:
    EVP_MD_CTX *md;
    const EVP_MD *hash_id;
    int hash_len;
};

#endif // HASHFUNCTION_H
