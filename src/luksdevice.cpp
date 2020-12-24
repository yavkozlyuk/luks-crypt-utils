#include "luksdevice.h"


#include "pbkdf.h"


#include <netinet/in.h>
#include <stdlib.h>
#include "logger.h"
#include "random.h"
#include "utils.h"
#include <memory.h>
#include <assert.h>
#include "afutils.h"
#include "opensslcryptoprovider.h"
#include "ioutils.h"
//#include <sys/stat.h>
#include <sys/ioctl.h>
#include <linux/fs.h>


extern int opt_keyfile_offset;
extern const char* opt_key_file;
extern int opt_keyfile_size;
extern int opt_timeout;
extern const char* opt_master_key_file;
extern Logger* logger;
extern Random* randomObj;


LuksDevice::LuksDevice() {
    this->alignment = 0;
    this->blockSize = 0;
    this->pbkdf.flags = 0;
    this->pbkdf.hash = NULL;
    this->pbkdf.iterations = 0;
    this->pbkdf.type = NULL;
    this->pbkdf.timeMs = 0;
    this->hdr = new LuksPartitionHeader();
}

LuksDevice::~LuksDevice() {
    if (this->hdr)
        delete this->hdr;
    if (this->path)
        free(this->path);
    if (this->type)
        free(this->type);
    if (this->pbkdf.hash)
        free(CONST_CAST(void*)this->pbkdf.hash);
    //if (this->pbkdf.type)
    //    free(CONST_CAST(void*)this->pbkdf.type);
    if (this->storageKey)
           this->storageKey.reset();
}

int LuksDevice::init(const char* devicePath) {
    if (!devicePath)
        return -EINVAL;
    this->path = strdup(devicePath);
    this->rngType = 0;
    this->type = NULL;
    return 0;
}


int LuksDevice::load(const char* requested_type, int require_header, int repair) {
    int r, version = 0;
    LuksPartitionHeader* luksHdr = new LuksPartitionHeader();


    if (Utils::isLUKS1(requested_type) || version == 1) {

        if (!(this->pbkdf.type) || strcmp(this->pbkdf.type, CRYPT_KDF_PBKDF2)) {
            this->pbkdf.type = CRYPT_KDF_PBKDF2;
        }
        r = readHdr(luksHdr, require_header, repair);//LUKS_read_phdr(&hdr, require_header, repair, cd);

        if (r)
            goto out;

        if (!this->type && !(this->type = strdup(CRYPT_LUKS1))) {
            r = -ENOMEM;
            goto out;
        }


        /* Set hash to the same as in the loaded header */
        if (!(this->pbkdf.hash) || strcmp(this->pbkdf.hash, luksHdr->getHashSpec())) {

            if (this->pbkdf.hash)
                free(CONST_CAST(void*)this->pbkdf.hash);
            this->pbkdf.hash = strdup(luksHdr->getHashSpec());
            if (!this->pbkdf.hash) {
                r = -ENOMEM;
                goto out;
            }
        }

        if (this->hdr)
            delete this->hdr;
        this->hdr = luksHdr;
    }
    else {
        if (version > 2)
            Logger::error("Unsupported LUKS version %d.", version);
        r = -EINVAL;
    }
out:
    if (r)
        delete luksHdr;
    return r;
}

int LuksDevice::load(const char* requested_type) {
    return this->load(requested_type, 1, 0);
}
/* Check that kernel supports requested cipher by decryption of one sector */
//LUKS_check_cipher
static int checkCipher(LuksDevice* device, size_t keylength, const char* cipher, const char* cipherMode) {
    int r;
    StorageKey* empty_key;
    char buf[SECTOR_SIZE];

    Logger::debug("Checking if cipher %s-%s is usable.", cipher, cipherMode);

    empty_key = new StorageKey(keylength, NULL);
    if (!empty_key)
        return -ENOMEM;

    /* No need to get KEY quality random but it must avoid known weak keys. */
    r = randomObj->getRandom(empty_key->getKey(), empty_key->getKeySize());
    if (!r)
        r = device->decrypt((unsigned char*)buf, sizeof(buf), cipher, cipherMode, empty_key, 0);

    delete empty_key;
    Utils::memzero(buf, sizeof(buf));
    return r;
}
int keySlotRepair(LuksDevice* device, LuksPartitionHeader* phdr) {

    const unsigned char* sector = (const unsigned char*)phdr;
    StorageKey* vk;
    int i, bad, r, need_write = 0;

    if (phdr->getKeyBytes() != 16 && phdr->getKeyBytes() != 32 && phdr->getKeyBytes() != 64) {
        Logger::error("Non standard key size, manual repair required.");
        return -EINVAL;
    }
    /* cryptsetup 1.0 did not align to 4k, cannot repair this one */
    if (phdr->getKeySlotsOffset() < (LUKS_ALIGN_KEYSLOTS / SECTOR_SIZE)) {
        Logger::error("Non standard keyslots alignment, manual repair required.");
        return -EINVAL;
    }

    r = checkCipher(device, phdr->getKeyBytes(), phdr->getCipherName(), phdr->getCipherMode());
    if (r < 0)
        return -EINVAL;

    vk = new StorageKey(phdr->getKeyBytes(), NULL);

    Logger::warn("Repairing keyslots.");

    Logger::debug("Generating second header with the same parameters for check.");
    /* cipherName, cipherMode, hashSpec, uuid are already null terminated */
    /* payloadOffset - cannot check */
    LuksPartitionHeader* temp_phdr = new LuksPartitionHeader(*phdr);

    if (r < 0)
        goto out;

    for (i = 0; i < LUKS_NUMKEYS; ++i) {
        if (phdr->getKeySlot(i).active == LUKS_KEY_ENABLED) {
            Logger::debug("Skipping repair for active keyslot %i.", i);
            continue;
        }

        bad = 0;
        if (phdr->getKeySlot(i).keyMaterialOffset != temp_phdr->getKeySlot(i).keyMaterialOffset) {
            Logger::error("Keyslot %i: offset repaired (%u -> %u).", i, (unsigned)phdr->getKeySlot(i).keyMaterialOffset, (unsigned)temp_phdr->getKeySlot(i).keyMaterialOffset);
            phdr->setKeySlotKeyMaterialOffset(i, temp_phdr->getKeySlot(i).keyMaterialOffset);
            bad = 1;
        }

        if (phdr->getKeySlot(i).stripes != temp_phdr->getKeySlot(i).stripes) {
            Logger::error("Keyslot %i: stripes repaired (%u -> %u).", i, (unsigned)phdr->getKeySlot(i).stripes, (unsigned)temp_phdr->getKeySlot(i).stripes);
            phdr->setKeySlotPasswordStripes(i, temp_phdr->getKeySlot(i).stripes);
            bad = 1;
        }

        /* Known case - MSDOS partition table signature */
        if (i == 6 && sector[0x1fe] == 0x55 && sector[0x1ff] == 0xaa) {
            Logger::error("Keyslot %i: bogus partition signature.", i);
            bad = 1;
        }

        if (bad) {
            Logger::error("Keyslot %i: salt wiped.", i);
            phdr->setKeySlotActive(i, LUKS_KEY_DISABLED);
            phdr->setKeySlotPasswordSalt(i, (char)0x00);
            phdr->setKeySlotPasswordIterations(i, 0);
        }

        if (bad)
            need_write = 1;
    }

    /*
         * check repair result before writing because repair can't fix out of order
         * keyslot offsets and would corrupt header again
         */
    if (phdr->checkKeySlots())
        r = -EINVAL;
    else if (need_write) {
        Logger::warn("Writing LUKS header to disk.");
        //todo
        //r = LUKS_write_phdr(phdr, ctx);
    }
out:
    if (r)
        Logger::error("Repair failed.");
    delete vk;
    delete temp_phdr;
    return r;
}
//_check_and_convert_hdr
int checkAndConvertHdr(LuksDevice* device, LuksPartitionHeader* hdr, int requireDevice, int repair) {
    int r = 0;
    unsigned int i;
    char luksMagic[] = LUKS_MAGIC;

    if (memcmp(hdr->getMagic(), luksMagic, LUKS_MAGIC_L)) { /* Check magic */
        Logger::debug("LUKS header not detected.");
        if (requireDevice)
            Logger::error("Device %s is not a valid LUKS device.");
        return -EINVAL;
    }
    else if (hdr->setAndReturnVersion(ntohs(hdr->getVersion())) != 1) {	/* Convert every uint16/32_t item from network byte order */
        Logger::error("Unsupported LUKS version %d.", hdr->getVersion());
        return -EINVAL;
    }


    hdr->getHashSpec()[LUKS_HASHSPEC_L - 1] = '\0';

    if (HashFunction::hashSize(hdr->getHashSpec()) < LUKS_DIGEST_SIZE) {
        Logger::error("Requested LUKS hash %s is not supported.", hdr->getHashSpec());
        return -EINVAL;
    }

    /* Header detected */
    hdr->setPayloadOffset(ntohl(hdr->getPayloadOffset()));
    hdr->setKeyBytes(ntohl(hdr->getKeyBytes()));
    hdr->setMkDigestIter(ntohl(hdr->getMkDigestIter()));

    for (i = 0; i < LUKS_NUMKEYS; ++i) {
        hdr->convertKeySlot(i, ntohl);
    }

    if (hdr->checkKeySlots())
        r = -EINVAL;

    /* Avoid unterminated strings */
    hdr->getCipherName()[LUKS_CIPHERNAME_L - 1] = '\0';
    hdr->getCipherMode()[LUKS_CIPHERMODE_L - 1] = '\0';
    hdr->getUUID()[UUID_STRING_L - 1] = '\0';

    if (repair) {
        if (r == -EINVAL)
            r = keySlotRepair(device, hdr);
        else
            Logger::warn("No known problems detected for LUKS header.");
    }

    return r;
}
//LUKS_read_phdr
int LuksDevice::readHdr(LuksPartitionHeader* hdr, int requireDevice, int repair) {
    ssize_t hdr_size = sizeof(LuksPartitionHeader);
    int devfd = 0, r = 0;

    /* LUKS header starts at offset 0, first keyslot on LUKS_ALIGN_KEYSLOTS */
    assert(hdr_size <= LUKS_ALIGN_KEYSLOTS);

    if (repair && !requireDevice)
        return -EINVAL;

    Logger::debug("Reading LUKS header of size %zu from device %s", hdr_size, path);

    devfd = open(path, O_RDONLY);
    if (devfd < 0) {
        Logger::error("Cannot open device %s.", path);
        return -EINVAL;
    }

    if (IOUtils::readBlockwise(devfd, this->getBlockSize(), this->getAlignment(), hdr, hdr_size) < hdr_size)
        r = -EIO;
    else
        r = checkAndConvertHdr(this, hdr, requireDevice, repair);

    //if (!r)
    //r = LUKS_check_device_size(ctx, hdr, 0);


    close(devfd);
    return r;
}
#ifndef LOOP_SET_CAPACITY
#define LOOP_SET_CAPACITY 0x4C07
#endif

int crypt_loop_resize(const char* loop) {
    int loop_fd = -1, r = 1;

    loop_fd = open(loop, O_RDONLY);
    if (loop_fd < 0)
        return 1;

    if (!ioctl(loop_fd, LOOP_SET_CAPACITY, 0))
        r = 0;

    close(loop_fd);
    return r;
}
/* For a file, allocate the required space */
int device_fallocate(LuksDevice* device, uint64_t size) {
    struct stat st;
    int devfd, r = -EINVAL;

    devfd = open(device->getPath(), O_RDWR);
    if (devfd == -1)
        return -EINVAL;

    if (!fstat(devfd, &st) && S_ISREG(st.st_mode) &&
            !posix_fallocate(devfd, 0, size)) {
        r = 0;
        if (device->getPath() && crypt_loop_resize(device->getPath()))
            r = -EINVAL;
    }

    close(devfd);
    return r;
}
/* Get data size in bytes */
int device_size(LuksDevice* device, uint64_t* size) {
    struct stat st;
    int devfd, r = -EINVAL;

    devfd = open(device->getPath(), O_RDONLY);
    if (devfd == -1)
        return -EINVAL;

    if (fstat(devfd, &st) < 0)
        goto out;

    if (S_ISREG(st.st_mode)) {
        *size = (uint64_t)st.st_size;
        r = 0;
    }
    else if (ioctl(devfd, BLKGETSIZE64, size) >= 0)
        r = 0;
out:
    close(devfd);
    return r;
}
//LUKS_device_sectors
size_t deviceSectors(LuksPartitionHeader* hdr) {
    int sorted_areas[LUKS_NUMKEYS] = { 0, 1, 2, 3, 4, 5, 6, 7 };

    LuksPartitionHeader::sortKeySlots(hdr, sorted_areas);

    return hdr->keySlots[sorted_areas[LUKS_NUMKEYS - 1]].keyMaterialOffset + AFUtils::splitSectors(hdr->keyBytes, LUKS_STRIPES);
}
ssize_t LuksDevice::getFileSize(const char* path) {
    int devfd;
    devfd = open(path, O_RDONLY);
    if (devfd != -1) {
        struct stat stat_buf;
        int rc = fstat(devfd, &stat_buf);
        close(devfd);
        return rc == 0 ? stat_buf.st_size : -1;
    }
    return -EPERM;
}
static int checkDeviceSize(LuksDevice* device, int falloc) {
    uint64_t dev_sectors, hdr_sectors;

    if (!device->getHdr()->getKeyBytes())
        return -EINVAL;

    if (device_size(device, &dev_sectors)) {
        Logger::debug("Cannot get device size for device %s.", device->getPath());
        return -EIO;
    }

    dev_sectors >>= SECTOR_SHIFT;
    hdr_sectors = deviceSectors(device->getHdr());
    Logger::debug("Key length %u, device size %" PRIu64 " sectors, header size %"
                  PRIu64 " sectors.", device->getHdr()->keyBytes, dev_sectors, hdr_sectors);

    if (hdr_sectors > dev_sectors) {
        /* If it is header file, increase its size */
        if (falloc && !device_fallocate(device, hdr_sectors << SECTOR_SHIFT))
            return 0;

        Logger::error("Device %s is too small. (LUKS1 requires at least %" PRIu64 " bytes.)", device->getPath(), hdr_sectors * SECTOR_SIZE);
        return -EINVAL;
    }

    return 0;
}
int LuksDevice::writeHdr() {

    ssize_t hdr_size = sizeof(LuksPartitionHeader);
    int devfd = 0;
    unsigned int i;
    LuksPartitionHeader convertedHeader;
    int r;

    Logger::debug("Updating LUKS header of size %zu on device %s", sizeof(LuksPartitionHeader), this->getPath());

    r = checkDeviceSize(this, 1);
    if (r)
        return r;

    devfd = open(this->getPath(), O_RDWR);
    if (devfd < 0) {
        if (errno == EACCES)
            Logger::error("Cannot write to device %s, permission denied.", this->getPath());
        else
            Logger::error("Cannot open device %s."), this->getPath();
        return -EINVAL;
    }

    memcpy(&convertedHeader, hdr, hdr_size);
    memset(&convertedHeader._padding, 0, sizeof(convertedHeader._padding));

    /* Convert every uint16/32_t item to network byte order */
    convertedHeader.version = htons(hdr->version);
    convertedHeader.payloadOffset = htonl(hdr->payloadOffset);
    convertedHeader.keyBytes = htonl(hdr->keyBytes);
    convertedHeader.mkDigestIter = htonl(hdr->mkDigestIter);
    for (i = 0; i < LUKS_NUMKEYS; ++i) {
        convertedHeader.keySlots[i].active = htonl(hdr->keySlots[i].active);
        convertedHeader.keySlots[i].iterations = htonl(hdr->keySlots[i].iterations);
        convertedHeader.keySlots[i].keyMaterialOffset = htonl(hdr->keySlots[i].keyMaterialOffset);
        convertedHeader.keySlots[i].stripes = htonl(hdr->keySlots[i].stripes);
    }

    r = IOUtils::writeBlockwise(devfd, this->getBlockSize(), this->getAlignment(), &convertedHeader, hdr_size) < hdr_size ? -EIO : 0;
    if (r)
        Logger::error("Error during update of LUKS header on device %s.", this->getPath());

    close(devfd);

    /* Re-read header from disk to be sure that in-memory and on-disk data are the same. */
    if (!r) {
        r = readHdr(hdr, 1, 0);
        if (r)
            Logger::error("Error re-reading LUKS header after update on device %s.", this->getPath());
    }

    return r;
}

int LuksDevice::createHeader(const char* cipher, const char* cipher_mode, const char* uuid, Key* key, Luks1Params* params) {
    int r;
    unsigned long required_alignment = DEFAULT_DISK_ALIGNMENT;
    unsigned long alignment_offset = 0;

    if (!cipher || !cipher_mode)
        return -EINVAL;


    if (!(this->type = strdup(CRYPT_LUKS1)))
        return -ENOMEM;

    if (key && key->getKey())
        this->setStorageKey(new StorageKey(*key));
    else
        this->setStorageKey(StorageKey::generateStorageKey(key->getKeySize()));

    if (!this->storageKey || !this->storageKey.get())
        return -ENOMEM;

    if (verifyPbkdfParams(this, &this->pbkdf)) {
        r = initPbkdfType(this, NULL, CRYPT_LUKS1);
        if (r)
            return r;
    }

    if (params && params->hash && strcmp(params->hash, this->pbkdf.hash)) {
        free(CONST_CAST(void*)this->pbkdf.hash);
        this->pbkdf.hash = strdup(params->hash);
        if (!this->pbkdf.hash)
            return -ENOMEM;
    }

    if (params && params->dataDevice) {
        required_alignment = params->dataAlignment * SECTOR_SIZE;
    }
    else if (params && params->dataAlignment) {
        required_alignment = params->dataAlignment * SECTOR_SIZE;
    }

    r = checkCipher(this, key->getKeySize(), cipher, cipher_mode);
    if (r < 0)
        return r;
    double PBKDF2_temp = (double)pbkdf.iterations * LUKS_MKD_ITERATIONS_MS / pbkdf.timeMs;
    if (PBKDF2_temp > (double)UINT32_MAX)
        return -EINVAL;
    uint32_t digestIter = at_least((uint32_t)PBKDF2_temp, LUKS_MKD_ITERATIONS_MIN);
    r = LuksPartitionHeader::generateHeader(this->hdr, this->storageKey.get(), digestIter, cipher, cipher_mode,
                                            this->pbkdf.hash, uuid, LUKS_STRIPES,
                                            required_alignment / SECTOR_SIZE,
                                            alignment_offset / SECTOR_SIZE, 0);
    if (r < 0)
        return r;


    /*r = LUKS_wipe_header_areas(&this->hdr, cd);
        if (r < 0) {
            Logger::error("Cannot wipe header on device %s."),
                mdata_device_path(cd));
            return r;
        }*/

    r = writeHdr();

    return r;
}

/* keyslot helpers */
//keyslot_verify_or_find_empty
static int verifyOrFindEmptyKeySlot(LuksDevice* device, int* keyslot) {
    KeySlotInfo ki;

    if (*keyslot == CRYPT_ANY_SLOT) {
        if (Utils::isLUKS1(device->getType()))
            *keyslot = LuksPartitionHeader::findEmptyKeySlot(device->getHdr());
        //else
        //	*keyslot = LUKS2_keyslot_find_empty(&cd->u.luks2.hdr, "luks2");
        if (*keyslot < 0) {
            Logger::error("All key slots full.");
            return -EINVAL;
        }
    }
    ki = LuksPartitionHeader::getKeySlotInfo(device->getHdr(), *keyslot);

    switch (ki) {
        case SLOT_INVALID:
            Logger::error("Key slot %d is invalid, please select between 0 and %d.", *keyslot, LUKS_NUMKEYS - 1);
            return -EINVAL;
        case SLOT_INACTIVE:
            break;
        default:
            Logger::error("Key slot %d is full, please select another one.", *keyslot);
            return -EINVAL;
    }

    Logger::debug("Selected keyslot %d.", *keyslot);
    return 0;
}
int LuksDevice::addKeySlotByStorageKey(int keyslot, StorageKey* key, Key* password) {
    StorageKey* vk = NULL;
    int r;

    if (!password || !password->getKey())
        return -EINVAL;

    Logger::debug("Adding new keyslot %d using volume key.", keyslot);

    r = verifyOrFindEmptyKeySlot(this, &keyslot);
    if (r < 0)
        return r;

    if (storageKey && storageKey->getKey())
        vk = new StorageKey(*storageKey);
    else if (this->storageKey)
        vk = new StorageKey(*this->storageKey);

    if (!vk)
        return -ENOMEM;

    r = this->getHdr()->verifyVolumeKey(vk);
    if (r < 0)
        Logger::error("Volume key does not match the volume.");
    else
        r = setKey(keyslot, password, vk);

    delete (vk);
    return (r < 0) ? r : keyslot;
}

int LuksDevice::addKeySlotByPassphrase(int keyslot, Key *passphrase, Key *newPassphrase) {
    int digest, r, active_slots;
    StorageKey *sk = NULL;

    Logger::debug("Adding new keyslot, existing passphrase %sprovided,"
                  "new passphrase %sprovided.", passphrase && passphrase->getKey() ? "" : "not ", newPassphrase && newPassphrase->getKey()  ? "" : "not ");

    if (!passphrase || !passphrase->getKey() || !newPassphrase || !newPassphrase->getKey())
        return -EINVAL;

    r = verifyOrFindEmptyKeySlot(this, &keyslot);
    if (r)
        return r;

    active_slots = this->getHdr()->countActiveKeySlots();

    if (active_slots == 0) {
        /* No slots used, try to use pre-generated key in header */
        if (this->storageKey) {
            sk = new StorageKey(*this->storageKey.get());
            r = sk ? 0 : -ENOMEM;
        } else {
            Logger::error("Cannot add key slot, all slots disabled and no volume key provided.");
            return -EINVAL;
        }
    } else if (active_slots < 0)
        return -EINVAL;
    else {
        /* Passphrase provided, use it to unlock existing keyslot */
        sk = new StorageKey();
        r = this->readKeyWithHdr(CRYPT_ANY_SLOT, passphrase, &sk);
    }

    if (r < 0)
        goto out;
    r = this->setKey(keyslot, newPassphrase, sk);


    if (r < 0)
        goto out;

    r = 0;
out:
    if (sk) delete sk;

    return keyslot;
}

int LuksDevice::addKeySlotByKeyFileDeviceOffset(int keyslot, const char *keyfile, size_t keyfile_size, uint64_t keyfile_offset, const char *new_keyfile, size_t new_keyfile_size, uint64_t new_keyfile_offset)
{
    if (!Utils::isLUKS1(this->type)) {
        return  -EINVAL;
    }
    int digest, r, active_slots;
    Key *password = NULL; Key *newPassword = NULL;
    StorageKey *sk = NULL;

    if (!keyfile || !new_keyfile)
        return -EINVAL;

    Logger::debug("Adding new keyslot, existing keyfile %s, new keyfile %s.",keyfile, new_keyfile);


    r = verifyOrFindEmptyKeySlot(this, &keyslot);
    if (r)
        return r;

    active_slots = this->getHdr()->countActiveKeySlots();

    if (active_slots == 0) {
        /* No slots used, try to use pre-generated key in header */
        if (this->storageKey) {
            sk = new StorageKey(*this->storageKey.get());
            r = sk ? 0 : -ENOMEM;
        } else {
            Logger::error("Cannot add key slot, all slots disabled and no volume key provided.");
            return -EINVAL;
        }
    } else {
        password = new Key();

        r = password->readKeyFromFile(keyfile,keyfile_offset, keyfile_size);
        if (r < 0)
            goto out;

        r = this->readKeyWithHdr(CRYPT_ANY_SLOT, password,&sk);
    }

    if (r < 0)
        goto out;
    newPassword = new Key();
    r = newPassword->readKeyFromFile(new_keyfile,new_keyfile_offset, new_keyfile_size);
    if (r < 0)
        goto out;


    r = this->setKey(keyslot, newPassword,sk);

out:
    if (password) delete(password);
    if (newPassword) delete newPassword;
    if (sk) delete sk;
    return keyslot;
}

int LuksDevice::destroyKeySlot(int keySlot)
{
    Logger::debug("Destroying keyslot %d.", keySlot);
    KeySlotInfo ki = this->getHdr()->getKeySlotInfo(keySlot);
    if (ki == SLOT_INVALID) {
        Logger::error("Key slot %d is invalid.", keySlot);
        return -EINVAL;
    }
    if (ki == SLOT_INACTIVE) {
        Logger::error("Key slot %d is not used.", keySlot);
        return -EINVAL;
    }

    unsigned int startOffset, endOffset;
    int r;
    r = this->readHdr(hdr, 1, 0);
    if (r)
        return r;

    r =  LuksPartitionHeader::setKeySlot(hdr, keySlot, 0);
    if (r) {
        Logger::error("Key slot %d is invalid, please select keyslot between 0 and %d.", keySlot, LUKS_NUMKEYS - 1);
        return r;
    }

    /* secure deletion of key material */
    startOffset = hdr->keySlots[keySlot].keyMaterialOffset;
    endOffset = startOffset + AFUtils::splitSectors(hdr->keyBytes, hdr->keySlots[keySlot].stripes);



    /* Wipe keyslot info */
    memset(&hdr->keySlots[keySlot].salt, 0, LUKS_SALT_SIZE);
    hdr->keySlots[keySlot].iterations = 0;

    r = this->writeHdr();

    return r;
}

int LuksDevice::changeKeySlotByPassphrase(int oldKeySlot, int newKeySlot, Key *passphrase, Key *newPassphrase){
    int digest = -1, r;
    StorageKey *sk = NULL;

    if (!passphrase || !passphrase->getKey() || !newPassphrase || !newPassphrase->getKey())
        return -EINVAL;

    Logger::debug("Changing passphrase from old keyslot %d to new %d.",oldKeySlot, newKeySlot);

    r = this->readKeyWithHdr(oldKeySlot, passphrase,&sk);

    if (r < 0)
        goto out;

    if (oldKeySlot != CRYPT_ANY_SLOT && oldKeySlot != r) {
        Logger::debug("Keyslot mismatch.");
        goto out;
    }
    oldKeySlot = r;

    if (newKeySlot == CRYPT_ANY_SLOT) {
        newKeySlot = LuksPartitionHeader::findEmptyKeySlot(this->getHdr());

        if (newKeySlot < 0)
            newKeySlot = oldKeySlot;
    }
    Logger::debug("Key change, old slot %d, new slot %d.", oldKeySlot, newKeySlot);


    if (oldKeySlot == newKeySlot) {
        Logger::debug("Key slot %d is going to be overwritten.", oldKeySlot);
        (void)this->destroyKeySlot(oldKeySlot);
    }
    r = this->setKey(newKeySlot, newPassphrase, sk);


    if (r >= 0 && oldKeySlot != newKeySlot)
        (void)this->destroyKeySlot(oldKeySlot);

    if (r < 0)
        Logger::error("Failed to swap new key slot.");
out:
    if (sk) delete sk;
    return newKeySlot;
}

int LuksDevice::setKey(unsigned int keyIndex, Key* password, StorageKey* sk) {
    StorageKey* derived_key;
    char* AfKey = NULL;
    size_t AFEKSize;
    struct PbkdfType* pbkdf;
    int r;

    if (hdr->keySlots[keyIndex].active != LUKS_KEY_DISABLED) {
        Logger::error("Key slot %d active, purge first.", keyIndex);
        return -EINVAL;
    }

    /* LUKS keyslot has always at least 4000 stripes according to specification */
    if (hdr->keySlots[keyIndex].stripes < 4000) {
        Logger::error("Key slot %d material includes too few stripes. Header manipulation?", keyIndex);
        return -EINVAL;
    }

    Logger::debug("Calculating data for key slot %d", keyIndex);
    pbkdf = this->getPbkdf();
    /*        r = crypt_benchmark_pbkdf_internal(ctx, pbkdf, vk->keylength);
        if (r < 0)
            return r;*/
    //assert(pbkdf->iterations);

    /*
                 * Final iteration count is at least LUKS_SLOT_ITERATIONS_MIN
                 */
    hdr->keySlots[keyIndex].iterations =
            at_least(pbkdf->iterations, LUKS_SLOT_ITERATIONS_MIN);
    Logger::debug("Key slot %d use %" PRIu32 " password iterations.", keyIndex,
                  hdr->keySlots[keyIndex].iterations);

    derived_key = new StorageKey(hdr->keyBytes, NULL);
    if (!derived_key)
        return -ENOMEM;

    r = randomObj->getRandom((unsigned char*)hdr->keySlots[keyIndex].salt, LUKS_SALT_SIZE);
    if (r < 0)
        goto out;

    r = OpenSSLCryptoProvider::pbdkf(CRYPT_KDF_PBKDF2, hdr->hashSpec, password,
                                     hdr->keySlots[keyIndex].salt, LUKS_SALT_SIZE,
                                     derived_key,
                                     hdr->keySlots[keyIndex].iterations);
    if (r < 0)
        goto out;

    /*
         * AF splitting, the masterkey stored in vk->key is split to AfKey
         */
    assert(sk->getKeySize() == hdr->keyBytes);
    AFEKSize = AFUtils::splitSectors(sk->getKeySize(), hdr->keySlots[keyIndex].stripes) * SECTOR_SIZE;
    AfKey = (char*)Utils::safeAlloc(AFEKSize);
    if (!AfKey) {
        r = -ENOMEM;
        goto out;
    }

    Logger::debug("Using hash %s for AF in key slot %d, %d stripes",
                  hdr->hashSpec, keyIndex, hdr->keySlots[keyIndex].stripes);
    r = AFUtils::split(sk->getKey(), (unsigned char*)AfKey, sk->getKeySize(), hdr->keySlots[keyIndex].stripes, hdr->hashSpec);
    if (r < 0)
        goto out;

    Logger::debug("Updating key slot %d [0x%04x] area.", keyIndex,
                  hdr->keySlots[keyIndex].keyMaterialOffset << 9);
    /* Encryption via dm */
    r = this->encrypt((unsigned char*)AfKey, AFEKSize, derived_key, hdr->keySlots[keyIndex].keyMaterialOffset);
    if (r < 0)
        goto out;

    /* Mark the key as active in phdr */
    r = LuksPartitionHeader::setKeySlot(hdr, (int)keyIndex, 1);
    if (r < 0)
        goto out;

    r = this->writeHdr();
    if (r < 0)
        goto out;

    r = 0;
out:
    Utils::safeFree(AfKey);
    delete(derived_key);
    return r;
}

int LuksDevice::dump() {
    std::cout << *this->hdr << std::endl;
    return 0;
}

int LuksDevice::dumpWithKey() {
    StorageKey* sk = new StorageKey();
    Key* password = new Key();
    int r;
    sk->setKeySize(this->hdr->getKeyBytes());
    r = password->readKey(NULL, opt_keyfile_offset, opt_keyfile_size, opt_key_file, opt_timeout, 0, 0, this->path);

    if (r < 0)
        goto out;

    r = this->readStorageKey(CRYPT_ANY_SLOT, password);
    Logger::passphraseMsg(r);
    Utils::checkSignal(&r);
    if (r < 0)
        goto out;
    Logger::keyslotMsg(r, UNLOCKED);

    if (opt_master_key_file) {
        r = sk->writeKey(opt_master_key_file);
        if (r < 0)
            goto out;
    }

    std::cout << hdr << std::endl;
    if (opt_master_key_file) {
        Logger::info("Key stored to file %s.\n", opt_master_key_file);
        goto out;
    }
    else {
        std::cout << sk << std::endl;
    }


out:
    delete password;
    delete sk;
    return r;
}
//crypt_volume_get_key
int LuksDevice::readStorageKey(int keyslot, Key* passphrase) {
    StorageKey* sk = new StorageKey();
    int key_len, r = -EINVAL;


    if (!passphrase) {
        r = -EINVAL;
        goto out;
    }

    key_len = this->hdr->getKeyBytes();
    sk->setKeySize(key_len);
    if (key_len < 0) {
        r = -EINVAL;
        goto out;
    }

    if (key_len > (int)sk->getKeySize()) {
        Logger::error("Volume key buffer too small.");
        r = -ENOMEM;
        goto out;
    }

    if (Utils::isLUKS1(this->type)) {
        r = readKeyWithHdr(keyslot, passphrase, &sk);
    } else
        Logger::error("This operation is not supported for %s crypt device.", this->type ? : "(none)");

    if (r >= 0) {
       this->setStorageKey(new StorageKey(*sk));
    }
out:
    delete sk;
    return r;
}
int LuksDevice::encryptBlockwise(int inFd, int outFd, LuksStorage* luksStorage, size_t dstLength, unsigned int inSector, unsigned int outSector) {
    int r = 0;
    struct stat st;
    unsigned char* dst = (unsigned char*)Utils::safeAlloc(dstLength);
    if (MISALIGNED_512(dstLength)) {
        r = -EINVAL;
        goto out;
    }
    if (IOUtils::readLseekBlockwise(inFd, this->getBlockSize(), this->getAlignment(), dst, dstLength, inSector * SECTOR_SIZE) < 0) {
        if (!fstat(inFd, &st) && (st.st_size < (off_t)dstLength))
            Logger::error("Device %s is too small.", this->path);
        else
            Logger::error("IO error while decrypting keyslot.");

        r = -EIO;
        goto out;
    }
    /* Decrypt buffer */
    r = luksStorage->encrypt(0, dstLength / SECTOR_SIZE, dst);
    if (IOUtils::writeLseekBlockwise(outFd, this->getBlockSize(), this->getAlignment(), dst, dstLength, outSector * SECTOR_SIZE) < 0) {
        if (!fstat(inFd, &st) && (st.st_size < (off_t)dstLength))
            Logger::error("Device %s is too small.", this->path);
        else
            Logger::error("IO error while writing decrypted block.");

        r = -EIO;
        goto out;
    }
    //todo check r;

out:
    Utils::safeFree(dst);
    return r;
}

int LuksDevice::decryptBlockwise(int inFd, int outFd, LuksStorage* luksStorage, size_t dstLength, unsigned int inSector, unsigned int outSector) {
    int r = 0;
    struct stat st;
    unsigned char* dst = (unsigned char*)Utils::safeAlloc(dstLength);
    if (MISALIGNED_512(dstLength)) {
        r = -EINVAL;
        goto out;
    }
    if (IOUtils::readLseekBlockwise(inFd, this->getBlockSize(), this->getAlignment(), dst, dstLength, inSector * SECTOR_SIZE) < 0) {
        if (!fstat(inFd, &st) && (st.st_size < (off_t)dstLength))
            Logger::error("Device %s is too small.", this->path);
        else
            Logger::error("IO error while decrypting keyslot.");

        r = -EIO;
        goto out;
    }
    /* Decrypt buffer */
    r = luksStorage->decrypt(0, dstLength, dst);
    if (IOUtils::writeLseekBlockwise(outFd, this->getBlockSize(), this->getAlignment(), dst, dstLength, outSector * SECTOR_SIZE) < 0) {
        if (!fstat(inFd, &st) && (st.st_size < (off_t)dstLength))
            Logger::error("Device %s is too small.", this->path);
        else
            Logger::error("IO error while writing decrypted block.");

        r = -EIO;
        goto out;
    }
    //todo check r;

out:
    Utils::safeFree(dst);
    return r;
}


char* LuksDevice::getPath() const {
    return path;
}

char* LuksDevice::getType() const {
    return type;
}

PbkdfType* LuksDevice::getPbkdf() {
    return &this->pbkdf;
}
void LuksDevice::setPbkdfFlags(int flags) {
    this->pbkdf.flags = flags;
}
int LuksDevice::encryptBlockwise(const char* srcPath, unsigned int sector) {
    ssize_t deviceSize = getFileSize(srcPath);

    LuksStorage luksStorage = LuksStorage();

    int devfd = -1, r = 0;
    int outfd = -1;
    unsigned int offset = 0;
    unsigned int outOffset = sector;
    /* Only whole sector reads supported */
    if (MISALIGNED_512(deviceSize)) {
        r = -EINVAL;
        goto out;
    }
    //2096640
    r = luksStorage.init(SECTOR_SIZE, this->hdr->getCipherName(), this->hdr->getCipherMode(), this->storageKey.get());

    if (r) {
        Logger::error("Userspace crypto wrapper cannot use %s-%s (%d).",
                      this->hdr->getCipherName(), this->hdr->getCipherMode(), r);
        goto out;
    }
    Logger::debug("Using userspace crypto wrapper to access keyslot area.");

    /* Read buffer from device */
    devfd = open(srcPath, O_RDONLY);
    if (devfd < 0) {
        Logger::error("Cannot open device %s.", srcPath);
        r = -EIO;
        goto out;
    }
    outfd = open(this->path, O_RDWR, S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH);
    if (outfd < 0) {
        Logger::error("Cannot open outputfile %s.", this->path);
        r = -EIO;
        close(devfd);
        goto out;
    }
    //for (unsigned int i = 0; i < deviceSize; i+=luksStorage.getSectorSize()) {
    Logger::debug("Decrypting: %ui out of %ui processed", offset * SECTOR_SIZE, deviceSize);
    encryptBlockwise(devfd, outfd, &luksStorage, deviceSize, offset++, outOffset++);
    //}

    close(devfd); close(outfd);

out:
    return r;
}

int LuksDevice::decryptBlockwise(const char* dstPath, unsigned int sector) {
    ssize_t deviceSize = getDeviceSize() - sector * SECTOR_SIZE;

    LuksStorage luksStorage = LuksStorage();

    int devfd = -1, r = 0;
    int outfd = -1;
    unsigned int offset = sector;
    unsigned int outOffset = 0;
    /* Only whole sector reads supported */
    if (MISALIGNED_512(deviceSize)) {
        r = -EINVAL;
        goto out;
    }
    //2096640
    r = luksStorage.init(SECTOR_SIZE, this->hdr->getCipherName(), this->hdr->getCipherMode(), this->storageKey.get());

    if (r) {
        Logger::error("Userspace crypto wrapper cannot use %s-%s (%d).",
                      this->hdr->getCipherName(), this->hdr->getCipherMode(), r);
        goto out;
    }
    Logger::debug("Using userspace crypto wrapper to access keyslot area.");

    /* Read buffer from device */
    devfd = open(this->path, O_RDONLY);
    if (devfd < 0) {
        Logger::error("Cannot open device %s.", this->path);
        r = -EIO;
        goto out;
    }
    outfd = open(dstPath, O_RDWR | O_CREAT | O_TRUNC, S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH);
    if (outfd < 0) {
        Logger::error("Cannot open outputfile %s.", dstPath);
        r = -EIO;
        close(devfd);
        goto out;
    }
    //for (unsigned int i = 0; i < deviceSize; i+=luksStorage.getSectorSize()) {
    Logger::debug("Decrypting: %ui out of %ui processed", offset * SECTOR_SIZE, deviceSize);
    decryptBlockwise(devfd, outfd, &luksStorage, deviceSize, offset++, outOffset++);
    //}

    close(devfd); close(outfd);

out:
    return r;
}
//LUKS_decrypt_from_storage
int LuksDevice::decrypt(unsigned char* dst, size_t dstLength, StorageKey* vk, unsigned int sector) {
    return decrypt(dst, dstLength, this->hdr->getCipherName(), this->hdr->getCipherMode(), vk, sector);
}
//LUKS_decrypt_from_storage
int LuksDevice::decrypt(unsigned char* dst, size_t dstLength, const char* cipher, const char* cipherMode, StorageKey* vk, unsigned int sector) {
    LuksStorage* luksStorage = new LuksStorage();
    struct stat st;
    int devfd = -1, r = 0;
    /* Only whole sector reads supported */
    if (MISALIGNED_512(dstLength)) {
        r = -EINVAL;
        goto out;
    }

    r = luksStorage->init(SECTOR_SIZE, cipher, cipherMode, vk);

    if (r) {
        Logger::error("Userspace crypto wrapper cannot use %s-%s (%d).",
                      this->hdr->getCipherName(), this->hdr->getCipherMode(), r);
        goto out;
    }

    Logger::debug("Using userspace crypto wrapper to access keyslot area.");

    /* Read buffer from device */
    devfd = open(this->path, O_RDONLY);
    if (devfd < 0) {
        Logger::error("Cannot open device %s.", this->path);
        r = -EIO;
        goto out;
    }

    if (IOUtils::readLseekBlockwise(devfd, this->getBlockSize(), this->getAlignment(), dst, dstLength, sector * SECTOR_SIZE) < 0) {
        if (!fstat(devfd, &st) && (st.st_size < (off_t)dstLength))
            Logger::error("Device %s is too small.", this->path);
        else
            Logger::error("IO error while decrypting keyslot.");

        close(devfd);
        r = -EIO;
        goto out;
    }

    close(devfd);

    /* Decrypt buffer */
    r = luksStorage->decrypt(0, dstLength /*/ SECTOR_SIZE*/, dst);

out:

    delete luksStorage;
    return r;
}

int LuksDevice::encrypt(unsigned char* src, size_t srcLength, StorageKey* vk, unsigned int sector) {
    LuksStorage* luksStorage = new LuksStorage();
    struct stat st;
    int devfd = -1, r = 0;
    /* Only whole sector reads supported */
    if (MISALIGNED_512(srcLength)) {
        r = -EINVAL;
        goto out;
    }

    r = luksStorage->init(SECTOR_SIZE, this->hdr->getCipherName(), this->hdr->getCipherMode(), vk);

    if (r) {
        Logger::error("Userspace crypto wrapper cannot use %s-%s (%d).",
                      this->hdr->getCipherName(), this->hdr->getCipherMode(), r);
        goto out;
    }

    Logger::debug("Using userspace crypto wrapper to access keyslot area.");


    r = luksStorage->encrypt(0, srcLength / SECTOR_SIZE, src);
    delete luksStorage;

    if (r)
        return r;

    r = -EIO;

    /* Write buffer to device */
    devfd = open(this->getPath(), O_RDWR);
    if (devfd < 0)
        goto out;

    if (IOUtils::writeLseekBlockwise(devfd, this->getBlockSize(), this->getAlignment(), src, srcLength, sector * SECTOR_SIZE) < 0)
        goto out;

    r = 0;
out:
    if (devfd >= 0) {
        //device_sync(device, devfd);
        close(devfd);
    }
    if (r)
        Logger::error("IO error while encrypting keyslot.");

    return r;
}

int LuksDevice::backupHeader(const char *backupFile) {

}

int LuksDevice::restoreHeader(const char *backupFile) {

}
static size_t deviceFsBlockSizeFd(int fd) {
    size_t pageSize = Utils::getPageSize();

#ifdef HAVE_SYS_STATVFS_H
    struct statvfs buf;

    /*
     * NOTE: some filesystems (NFS) returns bogus blocksize (1MB).
     * Page-size io should always work and avoids increasing IO beyond aligned LUKS header.
     */
    if (!fstatvfs(fd, &buf) && buf.f_bsize && buf.f_bsize <= pageSize)
        return (size_t)buf.f_bsize;
#endif
    return pageSize;
}
static size_t blockSizeByFd(int fd, size_t* minSize) {
    struct stat st;
    size_t bsize;
    int arg;

    if (fstat(fd, &st) < 0)
        return 0;

    if (S_ISREG(st.st_mode))
        bsize = deviceFsBlockSizeFd(fd);
    else {
        if (ioctl(fd, BLKSSZGET, &arg) < 0)
            bsize = Utils::getPageSize();
        else
            bsize = (size_t)arg;
    }

    if (!minSize)
        return bsize;

    if (S_ISREG(st.st_mode)) {
        /* file can be empty as well */
        if (st.st_size > (ssize_t)bsize)
            *minSize = bsize;
        else
            *minSize = st.st_size;
    }
    else {
        /* block device must have at least one block */
        *minSize = bsize;
    }

    return bsize;
}
size_t LuksDevice::getBlockSize() {
    if (blockSize)
        return blockSize;

    int fd;
    fd = open(path, O_RDONLY);
    if (fd >= 0) {
        this->blockSize = blockSizeByFd(fd, NULL);
        close(fd);
    }

    if (!this->blockSize)
        Logger::error("Cannot get block size for device %s.", this->path);

    return this->blockSize;
}

void LuksDevice::setBlockSize(const size_t& value) {
    blockSize = value;
}
static size_t deviceAlignmentFd(int devfd) {
    long alignment = DEFAULT_MEM_ALIGNMENT;

#ifdef _PC_REC_XFER_ALIGN
    alignment = fpathconf(devfd, _PC_REC_XFER_ALIGN);
    if (alignment < 0)
        alignment = DEFAULT_MEM_ALIGNMENT;
#endif
    return (size_t)alignment;
}
size_t LuksDevice::getAlignment() {
    int devfd;

    if (!this->alignment) {
        devfd = open(this->path, O_RDONLY);
        if (devfd != -1) {
            this->alignment = deviceAlignmentFd(devfd);
            close(devfd);
        }
    }

    return this->alignment;
}

LuksPartitionHeader* LuksDevice::getHdr() const {
    return hdr;
}

ssize_t LuksDevice::getDeviceSize() {
    return getFileSize(this->path);
}



int LuksDevice::readKeyWithHdr(int keyIndex, Key* password, StorageKey** sk) {
    unsigned int i;
    int r;

    *sk = new StorageKey(this->hdr->getKeyBytes(), NULL);

    if (keyIndex >= 0) {
        r = readKParticularKeyWithHdr(keyIndex, password, *sk);
        return (r < 0) ? r : keyIndex;
    }

    for (i = 0; i < LUKS_NUMKEYS; i++) {
        r = readKParticularKeyWithHdr(i, password, *sk);
        if (r == 0)
            return i;

        /* Do not retry for errors that are no -EPERM or -ENOENT,
               former meaning password wrong, latter key slot inactive */
        if ((r != -EPERM) && (r != -ENOENT))
            return r;
    }
    /* Warning, early returns above */
    delete* sk;
    return -EPERM;
}

void LuksDevice::setStorageKey(StorageKey *key)
{
    if (this->storageKey)
        this->storageKey.reset();
    if (key)
    this->storageKey = std::shared_ptr<StorageKey>(key);
}

int LuksDevice::readKParticularKeyWithHdr(int keyIndex, Key* password, StorageKey* sk) {
    KeySlotInfo ki = this->hdr->getKeySlotInfo(keyIndex);

    Key* AfKey;
    int r;

    Logger::debug("Trying to open heh key slot %d [%s].", keyIndex, LuksPartitionHeader::slotStateAsStr(ki));

    if (ki < SLOT_ACTIVE)
        return -ENOENT;
    StorageKey* derivedKey = new StorageKey(this->hdr->getKeyBytes(), NULL);
    if (!derivedKey)
        return -ENOMEM;
    assert(sk->getKeySize() == this->hdr->getKeyBytes());
    AfKey = new Key(AFUtils::splitSectors(sk->getKeySize(), this->hdr->getKeySlot(keyIndex).stripes) * SECTOR_SIZE, NULL);

    if (!AfKey || !AfKey->getKey()) {
        r = -ENOMEM;
        goto out;
    }

    r = OpenSSLCryptoProvider::pbdkf(CRYPT_KDF_PBKDF2, this->hdr->getHashSpec(), password,
                                     this->hdr->getKeySlot(keyIndex).salt, LUKS_SALT_SIZE, derivedKey, this->hdr->getKeySlot(keyIndex).iterations);

    if (r < 0)
        goto out;
    Utils::coutHexStr("Hashed password", (const char*)derivedKey->getKey(), derivedKey->getKeySize());
    Logger::debug("Reading key slot %d area.", keyIndex);
    r = this->decrypt(AfKey->getKey(), AfKey->getKeySize(), derivedKey, this->hdr->getKeySlot(keyIndex).keyMaterialOffset);
    if (r < 0)
        goto out;


    r = AFUtils::merge((const unsigned char*)AfKey->getKey(), (unsigned char*)sk->getKey(), sk->getKeySize(), this->hdr->getKeySlot(keyIndex).stripes, this->hdr->getHashSpec());

    if (r < 0)
        goto out;

    r = OpenSSLCryptoProvider::verifyKey(this->hdr, sk);

    /* Allow only empty passphrase with null cipher */
    if (!r && !strcmp(this->hdr->getCipherName(), "cipher_null") && password->getKeySize())
        r = -EPERM;
out:
    delete AfKey;
    delete derivedKey;
    return r;
}

