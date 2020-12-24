#pragma once
#ifndef STORAGEKEY_H
#define STORAGEKEY_H

#include <sys/types.h>
#include <cstdint>
#include <stdexcept>
#include <limits>
#include <string>
#include <string.h>
#include <memory>
#include "key.h"

enum {
    CRYPT_RND_NORMAL = 0, CRYPT_RND_KEY = 1, CRYPT_RND_SALT = 2
};

class StorageKey : public Key {
public:
    StorageKey();

    StorageKey(size_t keylength, const char *key);

    StorageKey(StorageKey &key);

    StorageKey(Key &key);

    virtual ~StorageKey();

    void setDescription(const char *keyDescription);

    void setId(int id);

    int getId();

    void addNext(std::shared_ptr<StorageKey> stKey);

    void addNext(StorageKey *stKey);

    StorageKey *getNext();

    StorageKey *getById(int id);

    char *getDescription() const;

    void setNext(std::shared_ptr<StorageKey> stKey);

    void setNext(StorageKey *stKey);

    static StorageKey *generateStorageKey(size_t keyLength);

private:
    int id;
    char *description;
    std::shared_ptr<StorageKey> next;
};

#endif // STORAGEKEY_H
