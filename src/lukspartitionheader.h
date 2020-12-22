#ifndef LUKSPARTITIONHEADER_H
#define LUKSPARTITIONHEADER_H
#include <sys/types.h>
#include <stdlib.h>
#include <unistd.h>
#include <inttypes.h>
#include "luksconstants.h"
#include <iostream>
#include "storagekey.h"

//LUKS data types are BIG ENDIAN (network byte order)
struct KeySlot {
    uint32_t active;
    uint32_t iterations;
    char salt[LUKS_SALT_SIZE];
    uint32_t keyMaterialOffset;
    uint32_t stripes;
};

struct LuksPartitionHeader {
    friend std::ostream &operator<<(std::ostream& os, const LuksPartitionHeader& obj);
    uint16_t getVersion() const;
    void setVersion(const uint16_t &value);
    uint16_t setAndReturnVersion(const uint16_t &value);

    uint32_t getPayloadOffset() const;
    void setPayloadOffset(const uint32_t &value);

    uint32_t getKeyBytes() const;
    void setKeyBytes(const uint32_t &value);

    uint32_t getMkDigestIter() const;
    void setMkDigestIter(const uint32_t &value);
    KeySlotInfo getKeySlotInfo(int keySlotIndex);
    static const char* slotStateAsStr(KeySlotInfo info);
    struct KeySlot getKeySlot(int index);
    char* getHashSpec() const;
    char* getCipherName() const;
    char* getCipherMode() const;
    char* getMkDigestSalt() const;
    char* getUUID() const;
    char* getMkDigest() const;
    void setMagic(const char* magic);
    char* getMagic();
    int setUUID(const char *uuid);
    void convertKeySlot(int index, uint32_t (*converter)(uint32_t arg));
    void setKeySlotActive(int i, uint32_t active);
    void setKeySlotKeyMaterialOffset(int i, uint32_t keyMaterialOffset);
    void setKeySlotPasswordSalt(int i, char*  salt);
    void setKeySlotPasswordSalt(int i, char  salt);
    void setKeySlotPasswordIterations(int i, uint32_t iterations);
    void setKeySlotPasswordStripes(int i, uint32_t stripes);
    int checkKeySlots();
    size_t getKeySlotsOffset();
    static void sortKeySlots(LuksPartitionHeader *hdr, int *array);
    //LUKS_keyslot_find_empty
    static int findEmptyKeySlot(LuksPartitionHeader *hdr);
    //LUKS_keyslot_info
    static KeySlotInfo getKeySlotInfo(LuksPartitionHeader *hdr, int keyslot);
    //LUKS_keyslot_set
    static int setKeySlot(LuksPartitionHeader *hdr, int keyslot, int enable);
    //LUKS_keyslot_active_count
    int countActiveKeySlots();


    char magic[LUKS_MAGIC_L];
    uint16_t version;
    char cipherName[LUKS_CIPHERNAME_L];
    char cipherMode[LUKS_CIPHERMODE_L];
    char hashSpec[LUKS_HASHSPEC_L];
    uint32_t payloadOffset;
    uint32_t keyBytes;
    char mkDigest[LUKS_DIGEST_SIZE];
    char mkDigestSalt[LUKS_SALT_SIZE];
    uint32_t mkDigestIter;
    char uuid[UUID_STRING_L];
    struct KeySlot keySlots[LUKS_NUMKEYS];
    char _padding[432];
    //LUKS_generate_phdr
    static int generateHeader(LuksPartitionHeader *header, StorageKey* storageKey,uint32_t digestIter,
                              const char *cipherName, const char *cipherMode, const char *hashSpec,
                              const char *uuid, unsigned int stripes,unsigned int alignPayload, unsigned int alignOffset,
                              int detached_metadata_device);

    /* Check whether a volume key is invalid. */
    //LUKS_verify_volume_key
    int verifyVolumeKey(Key *vk);
};

#endif // LUKSPARTITIONHEADER_H
