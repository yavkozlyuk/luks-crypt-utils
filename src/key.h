#pragma once
#ifndef KEY_H
#define KEY_H

#include <sys/types.h>
#include <stdio.h>
#include <unistd.h>
#include <ctype.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <stdlib.h>
#include <iostream>

#define DEFAULT_PASSPHRASE_SIZE_MAX 512
#define DEFAULT_KEYFILE_SIZE_MAXKB 8192

class Key {
public:
    Key();

    Key(size_t size, const char *key);

    Key(Key &obj);

    virtual ~Key();

    friend std::ostream &operator<<(std::ostream &os, const Key &obj);

    int readKey(const char *file, size_t keySize);

    //tools_get_key
    int readKey(const char *prompt, uint64_t keyfileOffset, size_t keyfileSizeMax, const char *keyFile, int timeout,
                int verify, int pwquality, const char *device);

    int readKeyFromFile(const char *keyfile, uint64_t keyfileOffset, size_t key_size);


    size_t getKeySize() const;

    void setKeySize(const size_t &value);

    unsigned char *getKey() const;

    void setKey(unsigned char *value);

    int writeKey(const char *file);

protected:
    unsigned char *key = NULL;
    size_t keySize  = 0;

    int readKeyTty(const char *prompt, int timeout, int verify);
};

#endif // KEY_H
