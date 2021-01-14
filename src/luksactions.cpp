#include "luksactions.h"
#include "logger.h"
#include "utils.h"
#include "pbkdf.h"
#include "opensslcryptoprovider.h"

#include <iostream>
#include <fstream>

extern Logger *logger;
extern const char **action_argv;
extern int action_argc;
extern const char *null_action_argv[];

extern struct PbkdfType defaultLuks1;

const char *opt_master_key_file = NULL;
const char *opt_header_backup_file = NULL;
const char *opt_key_file = NULL;
int opt_keyfiles_count = 0;
const char *opt_keyfiles[MAX_KEYFILES];
const char *opt_uuid = NULL;
const char *opt_header_device = NULL;
const char *opt_new_header_device = NULL;
const char *opt_device = NULL;
const char *opt_output_file = NULL;
const char *opt_type = "luks1";
int opt_key_size = 0;
long opt_keyfile_size = 0;
const char *opt_new_key_file = NULL;
long opt_new_keyfile_size = 0;
uint64_t opt_keyfile_offset = 0;
uint64_t opt_new_keyfile_offset = 0;
int opt_key_slot = CRYPT_ANY_SLOT;
int opt_version_mode = 0;
int opt_timeout = 60;
int opt_align_payload = 0;
int opt_dump_master_key = 0;
int opt_perf_same_cpu_crypt = 0;
int opt_test_passphrase = 0;
//FIXME: check uint32 overflow for long type
const char *opt_pbkdf = NULL;
int opt_iteration_time = 0;
int opt_sector_size = SECTOR_SIZE;
int opt_verbose = 0;
int opt_debug = 0;
const char *opt_hash = NULL;
const char *opt_cipher = NULL;
int opt_verify_passphrase = 1;

long opt_pbkdf_memory = DEFAULT_LUKS2_MEMORY_KB;
long opt_pbkdf_parallel = DEFAULT_LUKS2_PARALLEL_THREADS;
long opt_pbkdf_iterations = 0;

const char *luksType(const char *type) {
    if (type && !strcmp(type, "luks2"))
        return CRYPT_LUKS2;

    if (type && !strcmp(type, "luks1"))
        return CRYPT_LUKS1;

    if (type && !strcmp(type, "luks"))
        return CRYPT_LUKS; /* NULL */

    if (type && *type)
        return type;

    return CRYPT_LUKS; /* NULL */
}

LuksActions::LuksActions() = default;

int LuksActions::action_isLUKS(void) {
    LuksDevice *device = new LuksDevice();
    int r;
    /* FIXME: argc > max should be checked for other operations as well */
    if (action_argc > 1) {
        Logger::info("Only one device argument for isLuks operation is supported.");
        r = -ENODEV;
        goto out;
    }

    if ((r = device->init(Utils::uuidOrDeviceHeader(NULL))))
        goto out;


    r = device->load(luksType(CRYPT_LUKS1));
out:
    delete device;
    return r;
};

int LuksActions::action_readHeader(void) {
    LuksDevice *device = new LuksDevice();
    int r;

    if (!opt_device && !opt_header_device) {
        Logger::error("Input device/header must be given");
        return -EINVAL;
    }

    if ((r = device->init(Utils::uuidOrDeviceHeader(NULL))))
        goto out;

    if ((r = device->load(luksType(opt_type)))) {
        Logger::error("Device %s is not a valid LUKS device->", Utils::uuidOrDeviceHeader(NULL));
        goto out;
    }

    if (opt_dump_master_key)
        r = device->dumpWithKey();
    else
        r = device->dump();
out:
    delete device;
    return r;
};

int LuksActions::action_decrypt(void) {
    LuksDevice *device = new LuksDevice();
    StorageKey *sk = new StorageKey();
    Key *password = new Key();
    char *outFile = NULL;
    int r;

    if ((r = device->init(Utils::uuidOrDeviceHeader(NULL))))
        goto out;

    if ((r = device->load(luksType(opt_type)))) {
        Logger::error("Device %s is not a valid LUKS device->", Utils::uuidOrDeviceHeader(NULL));
        goto out;
    }

    sk->setKeySize(device->getHdr()->getKeyBytes());

    r = password->readKey(NULL, opt_keyfile_offset, opt_keyfile_size, opt_key_file, opt_timeout, 0, 0,
                          device->getPath());

    if (r < 0)
        goto out;


    r = device->readStorageKey(CRYPT_ANY_SLOT, password);

    Logger::passphraseMsg(r);
    Utils::checkSignal(&r);
    if (r < 0)
        goto out;
    Logger::keyslotMsg(r, UNLOCKED);
    if (opt_output_file) {
        outFile = strdup(opt_output_file);
    } else {
        outFile = (char *) malloc(1024);
        sprintf(outFile, "%s_decrypted", (const char *) device->getPath());
        outFile[1023] = '\0';
    }
    r = device->decryptBlockwise(outFile, device->getHdr()->getPayloadOffset());
out:
    if (r == 0)
        Logger::info("Device %s was successfully decrypted. Outfile: %s", device->getPath(), outFile);
    delete device;
    delete sk;
    delete password;
    if (outFile)
        free(outFile);
    return r;
};

int LuksActions::action_reencrypt(void) {
    LuksDevice *oldDevice = new LuksDevice();
    StorageKey *sk = new StorageKey();
    Key *password = new Key();
    char *reencryptedFile = NULL, *tmpFile = NULL,*msg = NULL;
    int r = -EINVAL, keysize, fd, created = 0;
    struct stat st;
    const char *type;
    char cipher[MAX_CIPHER_LEN], cipher_mode[MAX_CIPHER_LEN];
    Key *key = NULL;
    LuksDevice *newDevice = NULL;
    void *params;
    struct Luks1Params params1 = {
        .hash = opt_hash ?: DEFAULT_LUKS1_HASH,
                .dataAlignment = (size_t) opt_align_payload,
                .dataDevice = opt_header_device ? action_argv[0] : NULL,
    };
    if ((r = oldDevice->init(Utils::uuidOrDeviceHeader(NULL))))
        goto out;

    if ((r = oldDevice->load(luksType(opt_type)))) {
        Logger::error("Device %s is not a valid LUKS device->", Utils::uuidOrDeviceHeader(NULL));
        goto out;
    }

    sk->setKeySize(oldDevice->getHdr()->getKeyBytes());

    r = password->readKey(NULL, opt_keyfile_offset, opt_keyfile_size, opt_key_file, opt_timeout, 0, 0,
                          oldDevice->getPath());

    if (r < 0)
        goto out;


    r = oldDevice->readStorageKey(CRYPT_ANY_SLOT, password);

    Logger::passphraseMsg(r);
    Utils::checkSignal(&r);
    if (r < 0)
        goto out;
    Logger::keyslotMsg(r, UNLOCKED);
    tmpFile = (char *) malloc(1024);
    sprintf(tmpFile, "%s_tmp", (const char *) oldDevice->getPath());
    tmpFile[1023] = '\0';
    if (opt_output_file) {
        reencryptedFile = strdup(opt_output_file);
    } else {
        reencryptedFile = (char *) malloc(1024);
        sprintf(reencryptedFile, "%s_reencrypted", (const char *) oldDevice->getPath());
        reencryptedFile[1023] = '\0';
    }
    r = oldDevice->decryptBlockwise(tmpFile, oldDevice->getHdr()->getPayloadOffset());

    if (r == 0)
        Logger::info("Device %s was successfully decrypted. Outfile: %s", oldDevice->getPath(), tmpFile);



    if (password)
        delete password;
    password = NULL;
    type = luksType(opt_type);

    if (!type)
        type = DEFAULT_LUKS_FORMAT;
    if (!strcmp(type, CRYPT_LUKS1)) {
        params = &params1;

        if (opt_sector_size > SECTOR_SIZE) {
            Logger::error("Unsupported encryption sector size.");
            r = -EINVAL;
            goto out;
        }

    } else {
        r = -EINVAL;
        goto out;
    }
    if (reencryptedFile && stat(reencryptedFile, &st) < 0 && errno == ENOENT) {

        if (!Utils::confirmDialog("Header file does not exist, do you want to create it?","Operation aborted.\n"))
            return -EPERM;

        Logger::debug("Creating header file.");
        fd = open(reencryptedFile, O_CREAT | O_EXCL | O_WRONLY, S_IRUSR | S_IWUSR);
        if (fd == -1 || posix_fallocate(fd, 0, 4096 + LuksDevice::getFileSize(tmpFile)))
            Logger::error("Cannot create header file %s.", reencryptedFile);
        else {
            r = 0;
            created = 1;
        }
        if (fd != -1)
            close(fd);
        if (r < 0)
            return r;
    }
    newDevice = new LuksDevice();
    r = Utils::parseCipherNameAndMode(opt_cipher ?: DEFAULT_CIPHER(LUKS1), cipher, NULL, cipher_mode);
    if (r < 0) {
        Logger::error("No known cipher specification pattern detected.");
        goto out;
    }
    if ((r = newDevice->init(reencryptedFile))) {
        if (opt_header_device)
            Logger::error("Cannot use %s as on-disk header.", reencryptedFile);
        goto out;
    }
    if (!created) {
        r = asprintf(&msg, "This will overwrite data on %s irrevocably.", reencryptedFile);
        if (r == -1) {
            r = -ENOMEM;
            goto out;
        }

        r = Utils::confirmDialog(msg, "Operation aborted.\n") ? 0 : -EINVAL;
        free(msg);
        if (r < 0)
            goto out;
    }

    keysize = (opt_key_size ?: DEFAULT_LUKS1_KEYBITS) / 8;

    password = new Key();
    r = password->readKey(NULL, opt_keyfile_offset, opt_keyfile_size, opt_key_file, opt_timeout, 0, 0,
                          newDevice->getPath());
    if (r < 0)
        goto out;

    if (opt_master_key_file) {
        key = new Key(keysize, NULL);
        r = key->readKeyFromFile(opt_master_key_file, 0, keysize);
        if (r < 0)
            goto out;
    } else {
        key = new Key();
        key->setKey(NULL);
        key->setKeySize(keysize);
    }

    r = setPbkdfParams(newDevice, type);
    if (r) {
        Logger::error("Failed to set pbkdf parameters.");
        goto out;
    }
    r = newDevice->createHeader(cipher, cipher_mode, opt_uuid, key, (Luks1Params *) params);
    Utils::checkSignal(&r);
    if (r < 0)
        goto out;

    r = newDevice->addKeySlotByStorageKey(opt_key_slot, password);

    Logger::keyslotMsg(r, CREATED);
    newDevice->encryptBlockwise(tmpFile, newDevice->getHdr()->getPayloadOffset());
out:
    delete oldDevice;
    delete sk;
    delete (key);
    delete (password);
    delete newDevice;
    if (tmpFile) {
        if (std::ifstream(tmpFile))  {
            Logger::debug("Removing tmp file %s",  tmpFile);
             std::remove(tmpFile);
             bool failed = !std::ifstream("file1.txt");
                 if(failed) { std::perror("Error opening deleted file"); return 1; }
        }
        free(tmpFile);
    }
    if (reencryptedFile)
        free(reencryptedFile);
    return r;
};

int LuksActions::action_encrypt(void) {
    int r = -EINVAL, keysize, fd, created = 0;
    struct stat st;
    const char *devicePath, *type;
    char *outFile, *msg = NULL;
    char cipher[MAX_CIPHER_LEN], cipher_mode[MAX_CIPHER_LEN];
    Key *key = NULL, *password = NULL;
    /* Create header file (must contain at least one sector)? */

    if (!opt_device) {
        Logger::error("Input device must be given");
        return -EINVAL;
    }

    if (opt_output_file) {
        outFile = strdup(opt_output_file);
    } else {
        outFile = (char *) malloc(1024);
        sprintf(outFile, "%s_encrypted", (const char *) opt_device);
        outFile[1023] = '\0';
    }
    if (outFile && stat(outFile, &st) < 0 && errno == ENOENT) {

        if (!Utils::confirmDialog("Header file does not exist, do you want to create it?","Operation aborted.\n"))
            return -EPERM;

        Logger::debug("Creating header file.");
        fd = open(outFile, O_CREAT | O_EXCL | O_WRONLY, S_IRUSR | S_IWUSR);
        if (fd == -1 || posix_fallocate(fd, 0, 4096 + LuksDevice::getFileSize(opt_device)))
            Logger::error("Cannot create header file %s.", outFile);
        else {
            r = 0;
            created = 1;
        }
        if (fd != -1)
            close(fd);
        if (r < 0)
            return r;
    }

    LuksDevice *device = new LuksDevice();
    void *params;
    struct Luks1Params params1 = {
        .hash = opt_hash ?: DEFAULT_LUKS1_HASH,
                .dataAlignment = (size_t) opt_align_payload,
                .dataDevice = opt_header_device ? action_argv[0] : NULL,
    };
    type = luksType(opt_type);
    if (!type)
        type = DEFAULT_LUKS_FORMAT;
    if (!strcmp(type, CRYPT_LUKS1)) {
        params = &params1;

        if (opt_sector_size > SECTOR_SIZE) {
            Logger::error("Unsupported encryption sector size.");
            r = -EINVAL;
            goto out;
        }

    } else {
        r = -EINVAL;
        goto out;
    }
    devicePath = opt_device ?: action_argv[0];

    r = Utils::parseCipherNameAndMode(opt_cipher ?: DEFAULT_CIPHER(LUKS1), cipher, NULL, cipher_mode);
    if (r < 0) {
        Logger::error("No known cipher specification pattern detected.");
        goto out;
    }
    if ((r = device->init(outFile))) {
        if (opt_header_device)
            Logger::error("Cannot use %s as on-disk header.", devicePath);
        goto out;
    }
    if (!created) {
        r = asprintf(&msg, "This will overwrite data on %s irrevocably.", devicePath);
        if (r == -1) {
            r = -ENOMEM;
            goto out;
        }

        r = Utils::confirmDialog(msg, "Operation aborted.\n") ? 0 : -EINVAL;
        free(msg);
        if (r < 0)
            goto out;
    }

    keysize = (opt_key_size ?: DEFAULT_LUKS1_KEYBITS) / 8;

    password = new Key();
    r = password->readKey(NULL, opt_keyfile_offset, opt_keyfile_size, opt_key_file, opt_timeout, 0, 0,
                          device->getPath());
    if (r < 0)
        goto out;

    if (opt_master_key_file) {
        key = new Key(keysize, NULL);
        r = key->readKeyFromFile(opt_master_key_file, 0, keysize);
        if (r < 0)
            goto out;
    } else {
        key = new Key();
        key->setKey(NULL);
        key->setKeySize(keysize);
    }

    r = setPbkdfParams(device, type);
    if (r) {
        Logger::error("Failed to set pbkdf parameters.");
        goto out;
    }
    r = device->createHeader(cipher, cipher_mode, opt_uuid, key, (Luks1Params *) params);
    Utils::checkSignal(&r);
    if (r < 0)
        goto out;

    r = device->addKeySlotByStorageKey(opt_key_slot,password);

    Logger::keyslotMsg(r, CREATED);
    device->encryptBlockwise(devicePath, device->getHdr()->getPayloadOffset());
out:
    delete (key);
    delete (password);
    delete device;
    return r;
}

int LuksActions::action_addKey() {
    int r = -EINVAL, keysize = 0;
    StorageKey *key = NULL;
    Key *password = NULL, *newPassword = NULL;
    LuksDevice *luksDevice = new LuksDevice();

    if (!opt_device && !opt_header_device) {
        Logger::error("Input device/header must be given");
        return -EINVAL;
    }

    if ((r = luksDevice->init(Utils::uuidOrDeviceHeader(NULL))))
        goto out;

    if ((r = luksDevice->load(luksType(opt_type)))) {
        Logger::error("Device %s is not a valid LUKS device->", Utils::uuidOrDeviceHeader(NULL));
        goto out;
    }

    keysize = luksDevice->getHdr()->getKeyBytes();
    r = setPbkdfParams(luksDevice, luksDevice->getType());
    if (r) {
        Logger::error("Failed to set pbkdf parameters.");
        goto out;
    }

    if (opt_master_key_file) {
        key = new StorageKey(keysize, NULL);
        r = key->readKeyFromFile(opt_master_key_file, 0, keysize);
        if (r < 0)
            goto out;

        r = luksDevice->getHdr()->verifyVolumeKey(key);
        Utils::checkSignal(&r);
        if (r < 0)
            goto out;
        newPassword = new Key();
        r = newPassword->readKey("Enter new passphrase for key slot: ", opt_new_keyfile_offset, opt_new_keyfile_size,
                                 opt_new_key_file, opt_timeout, 1, 1, luksDevice->getPath());
        if (r < 0)
            goto out;

        r = luksDevice->addKeySlotByStorageKey(opt_key_slot, newPassword);
    } else if (opt_key_file && !Utils::isStdin(opt_key_file) &&
               opt_new_key_file && !Utils::isStdin(opt_new_key_file)) {
        r = luksDevice->addKeySlotByKeyFileDeviceOffset(opt_key_slot, opt_key_file, opt_keyfile_size,
                                                        opt_keyfile_offset,
                                                        opt_new_key_file, opt_new_keyfile_size, opt_new_keyfile_offset);
        Logger::passphraseMsg(r);
    } else {
        password = new Key();
        r = password->readKey("Enter any existing passphrase: ", opt_keyfile_offset, opt_keyfile_size, opt_key_file,
                              opt_timeout, 0, 0, luksDevice->getPath());

        if (r < 0)
            goto out;

        /* Check password before asking for new one */
        StorageKey *testKey = new StorageKey();
        r = luksDevice->readKeyWithHdr(CRYPT_ANY_SLOT, password, &testKey);
        Utils::checkSignal(&r);
        Logger::passphraseMsg(r);
        delete testKey;
        if (r < 0)
            goto out;
        Logger::keyslotMsg(r, UNLOCKED);

        newPassword = new Key();
        r = newPassword->readKey("Enter new passphrase for key slot: ", opt_new_keyfile_offset, opt_new_keyfile_size,
                                 opt_new_key_file, opt_timeout, 1, 1, luksDevice->getPath());
        if (r < 0)
            goto out;

        r = luksDevice->addKeySlotByPassphrase(opt_key_slot, password, newPassword);
    }
out:
    Logger::keyslotMsg(r, CREATED);
    if (password) delete password;
    if (newPassword) delete newPassword;
    if (key) delete key;
    if (luksDevice) delete luksDevice;
    return r;
}

int LuksActions::action_removeKey() {
    LuksDevice *luksDevice = new LuksDevice();
    StorageKey *testKey = NULL;
    Key *password = NULL;
    int r;

    if ((r = luksDevice->init(Utils::uuidOrDeviceHeader(NULL))))
        goto out;

    if ((r = luksDevice->load(luksType(opt_type)))) {
        Logger::error("Device %s is not a valid LUKS device->", Utils::uuidOrDeviceHeader(NULL));
        goto out;
    }
    password = new Key();
    r = password->readKey("Enter new passphrase to be deleted: ", opt_keyfile_offset, opt_keyfile_size, opt_key_file,
                          opt_timeout, 0, 0, luksDevice->getPath());
    if (r < 0)
        goto out;

    /* Check password before asking for new one */
    testKey = new StorageKey();
    r = luksDevice->readKeyWithHdr(CRYPT_ANY_SLOT, password, &testKey);
    delete testKey;
    Logger::passphraseMsg(r);
    Utils::checkSignal(&r);
    if (r < 0)
        goto out;
    Logger::keyslotMsg(r, UNLOCKED);

    opt_key_slot = r;
    Logger::warn("Key slot %d selected for deletion.", opt_key_slot);

    if (luksDevice->getHdr()->getKeySlotInfo(opt_key_slot) == SLOT_ACTIVE_LAST &&
            !Utils::confirmDialog("This is the last keyslot. \nDevice will become unusable after purging this key.", "Operation aborted, the keyslot was NOT wiped.\n")) {
          r = -EPERM;
          goto out;
        }

    r = luksDevice->destroyKeySlot(opt_key_slot);
    Logger::keyslotMsg(opt_key_slot, REMOVED);
out:
    if (password) delete password;
    if (luksDevice) delete luksDevice;
    return r;
}

int LuksActions::action_changeKey() {
    LuksDevice *luksDevice = new LuksDevice();
    StorageKey *testKey = NULL;
    Key *password = NULL, *newPassword = NULL;
    int r;

    if ((r = luksDevice->init(Utils::uuidOrDeviceHeader(NULL))))
        goto out;

    if ((r = luksDevice->load(luksType(opt_type)))) {
        Logger::error("Device %s is not a valid LUKS device->", Utils::uuidOrDeviceHeader(NULL));
        goto out;
    }
    r = setPbkdfParams(luksDevice, luksDevice->getType());
    if (r) {
        Logger::error("Failed to set pbkdf parameters.");
        goto out;
    }
    password = new Key();
    r = password->readKey("Enter passphrase to be changed: ", opt_keyfile_offset, opt_keyfile_size, opt_key_file,
                          opt_timeout, 0, 0, luksDevice->getPath());
    if (r < 0)
        goto out;

    /* Check password before asking for new one */
    testKey = new StorageKey();
    r = luksDevice->readKeyWithHdr(CRYPT_ANY_SLOT, password, &testKey);
    Utils::checkSignal(&r);
    Logger::passphraseMsg(r);
    delete testKey;
    if (r < 0)
        goto out;
    Logger::keyslotMsg(r, UNLOCKED);
    newPassword = new Key();
    r = newPassword->readKey("Enter new passphrase: ",
                             opt_new_keyfile_offset, opt_new_keyfile_size,
                             opt_new_key_file,
                             opt_timeout, 1, 1, luksDevice->getPath());;
    if (r < 0)
        goto out;

    r = luksDevice->changeKeySlotByPassphrase(opt_key_slot, opt_key_slot, password, newPassword);
    Logger::keyslotMsg(r, CREATED);
out:
    if (password) delete password;
    if (newPassword) delete newPassword;
    if (luksDevice) delete luksDevice;
    return r;
}

int LuksActions::action_killSlot() {
    LuksDevice *luksDevice = new LuksDevice();
    KeySlotInfo ki;
    int r;

    if ((r = luksDevice->init(Utils::uuidOrDeviceHeader(NULL))))
        goto out;

    if ((r = luksDevice->load(luksType(opt_type)))) {
        Logger::error("Device %s is not a valid LUKS device->", Utils::uuidOrDeviceHeader(NULL));
        goto out;
    }

    ki = luksDevice->getHdr()->getKeySlotInfo(opt_key_slot);
    switch (ki) {
        case SLOT_ACTIVE_LAST:
        case SLOT_ACTIVE:
        case SLOT_UNBOUND:
            Logger::warn("Keyslot %d is selected for deletion.", opt_key_slot);
            break;
        case SLOT_INACTIVE:
            Logger::error("Keyslot %d is not active.", opt_key_slot);
            /* fall through */
        case SLOT_INVALID:
            r = -EINVAL;
            goto out;
    }


    r = luksDevice->destroyKeySlot(opt_key_slot);
    Logger::keyslotMsg(opt_key_slot, REMOVED);
out:
    if (luksDevice) delete luksDevice;
    return r;
}

int LuksActions::action_UUID() {
    LuksDevice *luksDevice = new LuksDevice();
    const char *existing_uuid = NULL;
    int r;

    if ((r = luksDevice->init(Utils::uuidOrDeviceHeader(NULL))))
        goto out;


    if ((r = luksDevice->load(luksType(opt_type))))
        goto out;

    if (opt_uuid) {
        r = luksDevice->getHdr()->setUUID(opt_uuid);
        if (!r) luksDevice->writeHdr();
    } else {
        existing_uuid = luksDevice->getHdr()->getUUID();
        Logger::info("%s\n", existing_uuid ?: "");
        r = existing_uuid ? 0 : 1;
    }
out:
    delete luksDevice;
    return r;

}

int LuksActions::action_headerBackup(void) {
    LuksDevice *luksDevice = new LuksDevice();
    int r = 0;

    if (!opt_header_backup_file) {
        Logger::error("Option --header-backup-file is required.");
        goto out;
        r = -EINVAL;
    }


    if ((r = luksDevice->init(Utils::uuidOrDeviceHeader(NULL))))
        goto out;
    if ((r = luksDevice->load(luksType(CRYPT_LUKS1)))) {
        Logger::error("Device %s is not a valid LUKS device->", Utils::uuidOrDeviceHeader(NULL));
        goto out;
    }
    r = luksDevice->backupHeader(opt_header_backup_file);
out:
    delete luksDevice;
    return r;
}

int LuksActions::action_headerRestore(void) {
    LuksDevice *luksDevice = new LuksDevice();
    int r = 0;

    if (!opt_header_backup_file) {
        Logger::error("Option --header-backup-file is required.");
        goto out;
        r = -EINVAL;
    }

    if ((r = luksDevice->init(Utils::uuidOrDeviceHeader(NULL))))
        goto out;

    r = luksDevice->restoreHeader(opt_header_backup_file);
out:
    delete luksDevice;
    return r;
}

int LuksActions::action_listHash(void) {
    OpenSSLCryptoProvider::listHashAlgorithms();
    return 0;
}

int LuksActions::action_listCipher() {
    OpenSSLCryptoProvider::listCipherAlgorithms();
    return 0;
}



