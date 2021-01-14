#pragma once
#ifndef LUKSDEVICE_H
#define LUKSDEVICE_H

#include "storagekey.h"
#include "lukspartitionheader.h"
#include "luksstorage.h"

struct Luks1Params {
    const char *hash;        /**< hash used in LUKS header */
    size_t dataAlignment;   /**< data area alignment in 512B sectors, data offset is multiple of this */
    const char *dataDevice; /**< detached encrypted data device or @e NULL */
};

struct PbkdfType {
    char *type;         /**< PBKDF algorithm  */
    char *hash;         /**< Hash algorithm */
    uint32_t timeMs;         /**< Requested time cost [milliseconds] */
    uint32_t iterations;      /**< Iterations, 0 or benchmarked value. */
    uint32_t maxMemoryKb;   /**< Requested or benchmarked  memory cost [kilobytes] */
    uint32_t parallelThreads;/**< Requested parallel cost [threads] */
    uint32_t flags;           /**< CRYPT_PBKDF* flags */
};

class LuksDevice {
public:
    LuksDevice();

    virtual ~LuksDevice();

    int init(const char *devicePath);

    int load(const char *requested_type, int require_header, int repair);

    int load(const char *requested_type);

    int readHdr(LuksPartitionHeader *hdr, int requireDevice, int repair);

    //LUKS_write_phdr
    int writeHdr();

    int createHeader(const char *cipher, const char *cipher_mode, const char *uuid, Key *key, Luks1Params *params);

    //crypt_keyslot_add_by_volume_key
    int addKeySlotByStorageKey(int keyslot, Key *password);
    //crypt_keyslot_add_by_volume_key
    int addKeySlotByStorageKey(int keyslot, Key *password, StorageKey* storageKey);


    //crypt_keyslot_add_by_passphrase
    int addKeySlotByPassphrase(int keyslot, Key *passphrase, Key *newPassphrase);

    //crypt_keyslot_add_by_keyfile_device_offset
    int addKeySlotByKeyFileDeviceOffset(int keyslot, const char *keyfile, size_t keyfile_size, uint64_t keyfile_offset,
                                        const char *new_keyfile, size_t new_keyfile_size, uint64_t new_keyfile_offset);

    //crypt_keyslot_destroy -> LUKS_del_key
    int destroyKeySlot(int keySlot);

    //crypt_keyslot_change_by_passphrase
    int changeKeySlotByPassphrase(int keyslot_old, int keyslot_new, Key *passphrase, Key *newPassphrase);

    //LUKS_set_key
    int setKey(unsigned int keyIndex, Key *password, StorageKey *sk);

    int dump();

    int dumpWithKey();

    int readStorageKey(int keyslot, Key *passphrase);

    int decryptBlockwise(const char *dstPath, unsigned int sector);

    int encryptBlockwise(const char *dstPath, unsigned int sector);

    int decrypt(unsigned char *dst, size_t dstLength, StorageKey *vk, unsigned int sector);

    int decrypt(unsigned char *dst, size_t dstLength, const char *cipher, const char *cipherMode, StorageKey *vk,
                unsigned int sector);

    int encrypt(unsigned char *dst, size_t dstLength, StorageKey *vk, unsigned int sector);
    //crypt_header_backup
    int backupHeader(const char *backupFile);
    //crypt_header_restore
    int restoreHeader(const char *backupFile);

    //LUKS_hdr_restore
    int restoreHeader(const char *backupFile, LuksPartitionHeader* hdr);

    size_t getBlockSize();

    void setBlockSize(const size_t &value);

    size_t getAlignment();

    LuksPartitionHeader *getHdr() const;

    static ssize_t getFileSize(const char *path);

    ssize_t getDeviceSize();

    char *getPath() const;

    char *getType() const;

    struct PbkdfType *getPbkdf();

    void setPbkdfFlags(int flags);

    int readKeyWithHdr(int keyIndex, Key *password, StorageKey **sk);

    void setStorageKey(StorageKey *key);

private:
    int decryptBlockwise(int in, int out, LuksStorage *luksStorage, size_t dstLength, unsigned int inSector,
                         unsigned int outSector);

    int encryptBlockwise(int in, int out, LuksStorage *luksStorage, size_t dstLength, unsigned int inSector,
                         unsigned int outSector);

    char *type;
    char *path;

    unsigned int oDirect: 1;
    unsigned int initDone: 1;

    /* cached values */
    size_t alignment;
    size_t blockSize;

    std::shared_ptr<StorageKey> storageKey;
    int rngType;
    struct PbkdfType pbkdf;

    /* global context scope settings */
    unsigned keyInKeyring: 1;

    // FIXME: private binary headers and access it properly
    // through sub-library (LUKS1, TCRYPT)

    /* used in CRYPT_LUKS1 */
    LuksPartitionHeader *hdr;

    int readKParticularKeyWithHdr(int keyIndex, Key *password, StorageKey *sk);
};

#endif // LUKSDEVICE_H
