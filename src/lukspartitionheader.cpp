#include "lukspartitionheader.h"

#include <uuid/uuid.h>


#include "utils.h"
#include "logger.h"
#include "hashfunction.h"
#include "random.h"
#include "opensslcryptoprovider.h"

extern Random *randomObj;

uint16_t LuksPartitionHeader::getVersion() const {
    return version;
}

void LuksPartitionHeader::setVersion(const uint16_t &value) {
    version = value;
}

uint16_t LuksPartitionHeader::setAndReturnVersion(const uint16_t &value) {
    return version = value;
}

uint32_t LuksPartitionHeader::getPayloadOffset() const {
    return payloadOffset;
}

void LuksPartitionHeader::setPayloadOffset(const uint32_t &value) {
    payloadOffset = value;
}

uint32_t LuksPartitionHeader::getKeyBytes() const {
    return keyBytes;
}

void LuksPartitionHeader::setKeyBytes(const uint32_t &value) {
    keyBytes = value;
}

uint32_t LuksPartitionHeader::getMkDigestIter() const {
    return mkDigestIter;
}

void LuksPartitionHeader::setMkDigestIter(const uint32_t &value) {
    mkDigestIter = value;
}

KeySlotInfo LuksPartitionHeader::getKeySlotInfo(int keySlotIndex) {
    int i;

    if (keySlotIndex >= LUKS_NUMKEYS || keySlotIndex < 0)
        return SLOT_INVALID;

    if (this->keySlots[keySlotIndex].active == LUKS_KEY_DISABLED)
        return SLOT_INACTIVE;

    if (this->keySlots[keySlotIndex].active != LUKS_KEY_ENABLED)
        return SLOT_INVALID;

    for (i = 0; i < LUKS_NUMKEYS; i++)
        if (i != keySlotIndex && this->keySlots[i].active == LUKS_KEY_ENABLED)
            return SLOT_ACTIVE;

    return SLOT_ACTIVE_LAST;
}

const char *LuksPartitionHeader::slotStateAsStr(KeySlotInfo info) {
    switch (info) {
        case SLOT_INACTIVE:
            return "INACTIVE";
        case SLOT_ACTIVE:
            return "ACTIVE";
        case SLOT_ACTIVE_LAST:
            return "ACTIVE_LAST";
        case SLOT_INVALID:
        default:
            return "INVALID";
    }
}

KeySlot LuksPartitionHeader::getKeySlot(int index) {
    if (index < 0 || index >= LUKS_NUMKEYS) {
        throw new std::invalid_argument("invalid keyslot index");
    }
    return this->keySlots[index];
}

char *LuksPartitionHeader::getHashSpec() const {
    return (char *) hashSpec;
}

char *LuksPartitionHeader::getCipherName() const {
    return (char *) cipherName;
}

char *LuksPartitionHeader::getCipherMode() const {
    return (char *) cipherMode;
}

char *LuksPartitionHeader::getMkDigestSalt() const {
    return (char *) this->mkDigestSalt;
}

char *LuksPartitionHeader::getUUID() const {
    return (char *) this->uuid;
}

char *LuksPartitionHeader::getMkDigest() const {
    return (char *) this->mkDigest;
}

void LuksPartitionHeader::setMagic(const char *magic) {
    if (!magic)
        throw std::invalid_argument("Magic is not initialized");
    memcpy(this->magic, magic, LUKS_MAGIC_L);
}

char *LuksPartitionHeader::getMagic() {
    return (char *) this->magic;
}

int LuksPartitionHeader::setUUID(const char *uuid) {
    uuid_t partitionUuid;

    if (uuid && uuid_parse(uuid, partitionUuid) == -1) {
        Logger::error("Wrong LUKS UUID format provided.");
        return -EINVAL;
    }
    if (!uuid)
        uuid_generate(partitionUuid);

    uuid_unparse(partitionUuid, this->uuid);

    return 0;
}

void LuksPartitionHeader::convertKeySlot(int index, uint32_t (*converter)(uint32_t arg)) {
    this->keySlots[index].active = converter(this->keySlots[index].active);
    this->keySlots[index].iterations = converter(this->keySlots[index].iterations);
    this->keySlots[index].keyMaterialOffset = converter(this->keySlots[index].keyMaterialOffset);
    this->keySlots[index].stripes = converter(this->keySlots[index].stripes);
}

void LuksPartitionHeader::setKeySlotActive(int i, uint32_t active) {
    this->keySlots[i].active = active;
}

void LuksPartitionHeader::setKeySlotKeyMaterialOffset(int i, uint32_t keyMaterialOffset) {
    this->keySlots[i].keyMaterialOffset = keyMaterialOffset;
}

void LuksPartitionHeader::setKeySlotPasswordSalt(int i, char *salt) {
    memcpy(this->keySlots[i].salt, salt, LUKS_SALT_SIZE);
}

void LuksPartitionHeader::setKeySlotPasswordSalt(int i, char saltChar) {
    memset(this->keySlots[i].salt, saltChar, LUKS_SALT_SIZE);
}

void LuksPartitionHeader::setKeySlotPasswordIterations(int i, uint32_t iterations) {
    this->keySlots[i].iterations = iterations;
}

void LuksPartitionHeader::setKeySlotPasswordStripes(int i, uint32_t stripes) {
    this->keySlots[i].stripes = stripes;
}

//LUKS_sort_keyslots
void LuksPartitionHeader::sortKeySlots(LuksPartitionHeader *hdr, int *array) {
    int i, j, x;

    for (i = 1; i < LUKS_NUMKEYS; i++) {
        j = i;
        while (j > 0 && hdr->keySlots[array[j - 1]].keyMaterialOffset > hdr->keySlots[array[j]].keyMaterialOffset) {
            x = array[j];
            array[j] = array[j - 1];
            array[j - 1] = x;
            j--;
        }
    }
}

int LuksPartitionHeader::findEmptyKeySlot(LuksPartitionHeader *hdr) {
    int i;

    for (i = 0; i < LUKS_NUMKEYS; i++)
        if (hdr->keySlots[i].active == LUKS_KEY_DISABLED)
            break;

    if (i == LUKS_NUMKEYS)
        return -EINVAL;

    return i;
}

KeySlotInfo LuksPartitionHeader::getKeySlotInfo(LuksPartitionHeader *hdr, int keyslot) {
    int i;

    if (keyslot >= LUKS_NUMKEYS || keyslot < 0)
        return SLOT_INVALID;

    if (hdr->keySlots[keyslot].active == LUKS_KEY_DISABLED)
        return SLOT_INACTIVE;

    if (hdr->keySlots[keyslot].active != LUKS_KEY_ENABLED)
        return SLOT_INVALID;

    for (i = 0; i < LUKS_NUMKEYS; i++)
        if (i != keyslot && hdr->keySlots[i].active == LUKS_KEY_ENABLED)
            return SLOT_ACTIVE;

    return SLOT_ACTIVE_LAST;
}

int LuksPartitionHeader::setKeySlot(LuksPartitionHeader *hdr, int keyslot, int enable) {
    KeySlotInfo ki = getKeySlotInfo(hdr, keyslot);

    if (ki == SLOT_INVALID)
        return -EINVAL;

    hdr->keySlots[keyslot].active = enable ? LUKS_KEY_ENABLED : LUKS_KEY_DISABLED;
    Logger::debug("Key slot %d was %s in LUKS header.", keyslot, enable ? "enabled" : "disabled");
    return 0;
}

int LuksPartitionHeader::countActiveKeySlots() {
    int i, num = 0;

    for (i = 0; i < LUKS_NUMKEYS; i++)
        if (keySlots[i].active == LUKS_KEY_ENABLED)
            num++;

    return num;
}
/* Get size of struct luks_phdr with all keyslots material space */
//LUKS_calculate_device_sectors
static size_t calculateDeviceSectors(size_t keyLen) {
    size_t keyslot_sectors, sector;
    int i;

    keyslot_sectors = AFUtils::splitSectors(keyLen, LUKS_STRIPES);
    sector = LUKS_ALIGN_KEYSLOTS / SECTOR_SIZE;

    for (i = 0; i < LUKS_NUMKEYS; i++) {
        sector = Utils::sizeRoundUp(sector, LUKS_ALIGN_KEYSLOTS / SECTOR_SIZE);
        sector += keyslot_sectors;
    }

    return sector;
}

//LUKS_fix_header_compatible
static void fixHeaderCompatible(LuksPartitionHeader *header) {
    /* Old cryptsetup expects "sha1", gcrypt allows case insensitive names,
     * so always convert hash to lower case in header */
    Utils::_toLower(header->hashSpec, LUKS_HASHSPEC_L);

    /* ECB mode does not use IV but dmcrypt silently allows it.
     * Drop any IV here if ECB is used (that is not secure anyway).*/
    if (!strncmp(header->cipherMode, "ecb-", 4)) {
        memset(header->cipherMode, 0, LUKS_CIPHERMODE_L);
        strcpy(header->cipherMode, "ecb");
    }
}

//LUKS_generate_phdr
int LuksPartitionHeader::generateHeader(LuksPartitionHeader *header, StorageKey *storageKey, uint32_t digestIter,
                                        const char *cipherName, const char *cipherMode, const char *hashSpec,
                                        const char *uuid, unsigned int stripes, unsigned int alignPayload,
                                        unsigned int alignOffset,
                                        int detached_metadata_device) {
    unsigned int i = 0, hdr_sectors = calculateDeviceSectors(storageKey->getKeySize());
    size_t blocksPerStripeSet, currentSector;
    int r;
    uuid_t partitionUuid;
    char luksMagic[] = LUKS_MAGIC;

    /* For separate metadata device allow zero alignment */
    if (alignPayload == 0 && !detached_metadata_device)
        alignPayload = DEFAULT_DISK_ALIGNMENT / SECTOR_SIZE;

    if (alignPayload && detached_metadata_device && alignPayload < hdr_sectors) {
        Logger::error("Data offset for detached LUKS header must be ",
                      "either 0 or higher than header size (%d sectors).", hdr_sectors);
        return -EINVAL;
    }

    if (HashFunction::hashSize(hashSpec) < LUKS_DIGEST_SIZE) {
        Logger::error("Requested LUKS hash %s is not supported.", hashSpec);
        return -EINVAL;
    }

    if (uuid && uuid_parse(uuid, partitionUuid) == -1) {
        Logger::error("Wrong LUKS UUID format provided.");
        return -EINVAL;
    }
    if (!uuid)
        uuid_generate(partitionUuid);

    memset(header, 0, sizeof(LuksPartitionHeader));

    /* Set Magic */
    memcpy(header->magic, luksMagic, LUKS_MAGIC_L);
    header->version = 1;
    strncpy(header->cipherName, cipherName, LUKS_CIPHERNAME_L - 1);
    strncpy(header->cipherMode, cipherMode, LUKS_CIPHERMODE_L - 1);
    strncpy(header->hashSpec, hashSpec, LUKS_HASHSPEC_L - 1);

    header->keyBytes = storageKey->getKeySize();

    fixHeaderCompatible(header);

    Logger::debug("Generating LUKS header version %d using hash %s, %s, %s, MK %d bytes",
                  header->version, header->hashSpec, header->cipherName, header->cipherMode,
                  header->keyBytes);

    r = randomObj->getRandom((unsigned char *) header->mkDigestSalt, LUKS_SALT_SIZE);
    if (r < 0) {
        Logger::error("Cannot create LUKS header: reading random salt failed.");
        return r;
    }

    /* Compute master key digest */
    /*r = crypt_benchmark_pbkdf_internal(ctx, pbkdf, vk->keylength);
    if (r < 0)
        return r;
    assert(pbkdf->iterations);
    */

    header->mkDigestIter = digestIter;//at_least((uint32_t)PBKDF2_temp, LUKS_MKD_ITERATIONS_MIN);
    Key *key = new Key(LUKS_DIGEST_SIZE, NULL);
    r = OpenSSLCryptoProvider::pbdkf(CRYPT_KDF_PBKDF2, header->hashSpec, storageKey,
                                     header->mkDigestSalt, LUKS_SALT_SIZE, key, header->mkDigestIter);
    if (r < 0) {
        Logger::error("Cannot create LUKS header: header digest failed (using hash %s).",
                      header->hashSpec);
        delete key;
        return r;
    }
    memcpy(header->mkDigest, key->getKey(), LUKS_DIGEST_SIZE);
    currentSector = LUKS_ALIGN_KEYSLOTS / SECTOR_SIZE;
    blocksPerStripeSet = AFUtils::splitSectors(storageKey->getKeySize(), stripes);
    for (i = 0; i < LUKS_NUMKEYS; ++i) {
        header->keySlots[i].active = LUKS_KEY_DISABLED;
        header->keySlots[i].keyMaterialOffset = currentSector;
        header->keySlots[i].stripes = stripes;
        currentSector = Utils::sizeRoundUp(currentSector + blocksPerStripeSet,
                                           LUKS_ALIGN_KEYSLOTS / SECTOR_SIZE);
    }

    if (detached_metadata_device) {
        /* for separate metadata device use alignPayload directly */
        header->payloadOffset = alignPayload;
    } else {
        /* alignOffset - offset from natural device alignment provided by topology info */
        currentSector = Utils::sizeRoundUp(currentSector, alignPayload);
        header->payloadOffset = currentSector + alignOffset;
    }

    uuid_unparse(partitionUuid, header->uuid);

    Logger::debug("Data offset %d, UUID %s, digest iterations %" PRIu32,
                  header->payloadOffset, header->uuid, header->mkDigestIter);
    delete key;
    return 0;
}

int LuksPartitionHeader::verifyVolumeKey(Key *vk) {
    Key *key = new Key(LUKS_DIGEST_SIZE, NULL);
    if (OpenSSLCryptoProvider::pbdkf(CRYPT_KDF_PBKDF2, this->hashSpec, vk,
                                     this->mkDigestSalt, LUKS_SALT_SIZE,
                                     key,
                                     this->mkDigestIter) < 0) {
        delete key;
        return -EINVAL;
    }
    if (memcmp(key->getKey(), this->mkDigest, LUKS_DIGEST_SIZE)) {
        delete key;
        return -EPERM;
    }

    delete key;
    return 0;
}

//LUKS_check_keyslots
int LuksPartitionHeader::checkKeySlots() {
    int i, prev, next, sorted_areas[LUKS_NUMKEYS] = {0, 1, 2, 3, 4, 5, 6, 7};
    uint32_t secs_per_stripes = AFUtils::splitSectors(this->keyBytes, LUKS_STRIPES);

    sortKeySlots(this, sorted_areas);
    /* Check keyslot to prevent access outside of header and keyslot area */
    for (i = 0; i < LUKS_NUMKEYS; i++) {
        /* enforce stripes == 4000 */
        if (this->keySlots[i].stripes != LUKS_STRIPES) {
            Logger::debug("Invalid stripes count %u in keyslot %u.",
                          this->keySlots[i].stripes, i);
            Logger::error("LUKS keyslot %u is invalid.", i);
            return -1;
        }

        /* First sectors is the header itself */
        if (this->keySlots[i].keyMaterialOffset * SECTOR_SIZE < sizeof(this)) {
            Logger::debug("Invalid offset %u in keyslot %u.",
                          this->keySlots[i].keyMaterialOffset, i);
            Logger::error("LUKS keyslot %u is invalid.", i);
            return -1;
        }

        /* Ignore following check for detached header where offset can be zero. */
        if (this->payloadOffset == 0)
            continue;

        if (this->payloadOffset <= this->keySlots[i].keyMaterialOffset) {
            Logger::debug("Invalid offset %u in keyslot %u (beyond data area offset %u).",
                          this->keySlots[i].keyMaterialOffset, i,
                          this->payloadOffset);
            Logger::error("LUKS keyslot %u is invalid.", i);
            return -1;
        }

        if (this->payloadOffset < (this->keySlots[i].keyMaterialOffset + secs_per_stripes)) {
            Logger::debug("Invalid keyslot size %u (offset %u, stripes %u) in "
                          "keyslot %u (beyond data area offset %u).",
                          secs_per_stripes,
                          this->keySlots[i].keyMaterialOffset,
                          this->keySlots[i].stripes,
                          i, this->payloadOffset);
            Logger::error("LUKS keyslot %u is invalid.", i);
            return -1;
        }
    }

    /* check no keyslot overlaps with each other */
    for (i = 1; i < LUKS_NUMKEYS; i++) {
        prev = sorted_areas[i - 1];
        next = sorted_areas[i];
        if (this->keySlots[next].keyMaterialOffset <
            (this->keySlots[prev].keyMaterialOffset + secs_per_stripes)) {
            Logger::debug("Not enough space in LUKS keyslot %d.", prev);
            Logger::error("LUKS keyslot %u is invalid.", prev);
            return -1;
        }
    }
    /* do not check last keyslot on purpose, it must be tested in device size check */

    return 0;
}

//LUKS_keyslots_offset
size_t LuksPartitionHeader::getKeySlotsOffset() {
    int sorted_areas[LUKS_NUMKEYS] = {0, 1, 2, 3, 4, 5, 6, 7};

    sortKeySlots(this, sorted_areas);

    return this->keySlots[sorted_areas[0]].keyMaterialOffset;
}


std::ostream &operator<<(std::ostream &os, const LuksPartitionHeader &hdr) {
    std::cout << "Magic: " << hdr.magic << std::endl;
    std::cout << "version: " << hdr.version << std::endl;
    std::cout << "cipherName: " << hdr.cipherName << std::endl;
    std::cout << "cipher_mode: " << hdr.cipherMode << std::endl;
    std::cout << "hash_spec: " << hdr.hashSpec << std::endl;
    std::cout << "payload_offset: " << hdr.payloadOffset << std::endl;
    std::cout << "key_bytes: " << hdr.keyBytes << std::endl;
    Utils::coutHexStr("mk_digest", hdr.mkDigest, LUKS_DIGEST_SIZE);
    Utils::coutHexStr("mk_digest_salt", hdr.mkDigestSalt, LUKS_SALT_SIZE);
    std::cout << "mk_digest_iter: " << hdr.mkDigestIter << std::endl;
    std::cout << "uuid: " << hdr.uuid << std::endl;
    std::cout << "Keys: " << std::endl;
    for (int i = 0; i < LUKS_NUMKEYS; i++) {
        if (hdr.keySlots[i].active == LUKS_KEY_ENABLED) {
            std::cout << "Key Slot " << i << " ACTIVE " << std::endl;
            std::cout << "iterations: " << hdr.keySlots[i].iterations << std::endl;
            Utils::coutHexStr("salt", hdr.keySlots[i].salt, LUKS_SALT_SIZE);
            std::cout << "key_material_offset: " << hdr.keySlots[i].keyMaterialOffset << std::endl;
            std::cout << "stripes: " << hdr.keySlots[i].stripes << std::endl;
        } else {
            std::cout << "Key Slot " << i << ": DEAD" << std::endl;
        }
    }
    return os;
}
