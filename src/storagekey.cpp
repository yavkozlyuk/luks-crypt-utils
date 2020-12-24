#include "storagekey.h"

#include "utils.h"
#include "random.h"

#define CONST_CAST(x) (x)(uintptr_t)

extern Random *randomObj;

StorageKey::StorageKey() : Key() {

}

StorageKey::StorageKey(size_t keylength, const char *key) : Key(keylength, key) {
    this->id = -1;
    this->next = NULL;
}

StorageKey::StorageKey(StorageKey &key) : Key(key) {
    this->id = key.id;
    if (key.getDescription()) {
        this->description = strdup(key.getDescription());
    }
}

StorageKey::StorageKey(Key &key) : Key(key) {

}

StorageKey::~StorageKey() {

}

void StorageKey::setDescription(const char *keyDescription) {
    this->description = (char *) std::malloc(strlen(keyDescription));
    int r;
    if ((r = strcmp(this->description, keyDescription))) {
        throw r;
    }
}

void StorageKey::setId(int id) {
    this->id = id;
}

int StorageKey::getId() {
    return this->id;
}

void StorageKey::addNext(std::shared_ptr<StorageKey> stKey) {
    StorageKey *tmp;

    if (!stKey)
        return;

    tmp = this;

    while (tmp->next)
        tmp = tmp->next.get();

    tmp->setNext(stKey);
}

void StorageKey::addNext(StorageKey *stKey) {
    StorageKey *tmp;

    if (!stKey)
        return;

    tmp = this;

    while (tmp->next)
        tmp = tmp->next.get();

    tmp->setNext(stKey);
}

StorageKey *StorageKey::getNext() {
    return this->next.get();
}

StorageKey *StorageKey::getById(int id) {
    if (id < 0)
        return NULL;
    StorageKey *tmp = this;
    while (tmp && tmp->id != id)
        tmp = tmp->getNext();

    return tmp;
}

char *StorageKey::getDescription() const {
    return description;
}

void StorageKey::setNext(std::shared_ptr<StorageKey> stKey) {
    this->next = stKey;
}

void StorageKey::setNext(StorageKey *stKey) {
    this->next = std::shared_ptr<StorageKey>(stKey);
}

StorageKey *StorageKey::generateStorageKey(size_t keyLength) {
    int r;
    StorageKey *storageKey = new StorageKey(keyLength, NULL);
    if (!storageKey)
        return NULL;

    r = randomObj->getRandom(storageKey->getKey(), keyLength);
    if (r < 0) {
        delete storageKey;
        return NULL;
    }
    return storageKey;
}



