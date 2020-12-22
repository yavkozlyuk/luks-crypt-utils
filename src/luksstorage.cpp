#include "luksstorage.h"

LuksStorage::LuksStorage() {

}

LuksStorage::~LuksStorage() {

    Cipher::sectorIVDestroy(&this->cipherIV);

    if (this->cipher) {
        delete cipher;
        //crypt_cipher_destroy(ctx->cipher);
    }

    //memset(ctx, 0, sizeof(*ctx));
    //free(ctx);
}

int LuksStorage::init(size_t sector_size, const char *cipher, const char *cipher_mode, Key* key) {
    char mode_name[64];
    char *cipher_iv = NULL;
    int r = -EIO;

    if (sector_size < (1 << SECTOR_SHIFT) || sector_size > (1 << (SECTOR_SHIFT + 3)) || sector_size & (sector_size - 1))
        return -EINVAL;

    /* Remove IV if present */
    strncpy(mode_name, cipher_mode, sizeof(mode_name));
    mode_name[sizeof(mode_name) - 1] = 0;
    cipher_iv = strchr(mode_name, '-');
    if (cipher_iv) {
        *cipher_iv = '\0';
        cipher_iv++;
    }
    this->cipher = new Cipher();
    r = this->cipher->init(cipher, mode_name, key->getKey(), key->getKeySize());
    if (r) {
        //todo destroy
        //crypt_storage_destroy(s);
        return r;
    }

    r = Cipher::sectorIVInit(&this->cipherIV, cipher, mode_name, cipher_iv, key->getKey(), key->getKeySize(), sector_size);
    if (r) {		//todo destroy
        //crypt_storage_destroy(s);
        return r;
    }

    this->sectorSize = sector_size;
    this->ivShift = 0;

    return 0;
}

int LuksStorage::encrypt(uint64_t sector, size_t count, unsigned char *buffer) {
    unsigned int i;
    int r = 0;

    for (i = 0; i < count; i++) {
        r = Cipher::sectorIVGenerate(&this->cipherIV, sector + i);
        if (r)
            break;
        r = this->cipher->encrypt(&buffer[i * SECTOR_SIZE], &buffer[i * SECTOR_SIZE], SECTOR_SIZE, this->cipherIV.iv, this->cipherIV.ivSize);
        if (r)
            break;
    }

    return r;
}

int LuksStorage::decrypt(uint64_t iv_offset, uint64_t length, unsigned char *buffer) {
    uint64_t i;
    int r = 0;

    if (length & (this->sectorSize - 1))
        return -EINVAL;

    if (iv_offset & ((this->sectorSize >> SECTOR_SHIFT) - 1))
        return -EINVAL;

    for (i = 0; i < length; i += this->sectorSize) {
        r = Cipher::sectorIVGenerate(&this->cipherIV, (iv_offset + (i >> SECTOR_SHIFT)) >> this->ivShift);
        if (r)
            break;
        r = this->cipher->decrypt(&buffer[i], &buffer[i], this->sectorSize, this->cipherIV.iv, this->cipherIV.ivSize);
        if (r)
            break;
    }

    return r;
}

size_t LuksStorage::getSectorSize() const
{
    return sectorSize;
}

void LuksStorage::setSectorSize(const size_t &value)
{
    sectorSize = value;
}

