#pragma once
#ifndef LUKSSTORAGE_H
#define LUKSSTORAGE_H

#include <sys/types.h>
#include "cipher.h"
#include "luksconstants.h"
#include "key.h"

class LuksStorage {
public:
    LuksStorage();

    virtual ~LuksStorage();

    int init(size_t sector_size, const char *cipher, const char *cipher_mode, Key *key);

    int encrypt(uint64_t sector, size_t count, unsigned char *buffer);

    int decrypt(uint64_t iv_offset, uint64_t length, unsigned char *buffer);

    size_t getSectorSize() const;

    void setSectorSize(const size_t &value);

private:
    size_t sectorSize;
    unsigned ivShift;
    Cipher *cipher = NULL;
    SectorIV cipherIV;
};

#endif // LUKSSTORAGE_H
