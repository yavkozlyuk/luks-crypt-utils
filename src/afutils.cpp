#include "afutils.h"
#include "bitops.h"
#include "hashfunction.h"
#include "luksconstants.h"
#include "utils.h"
#include "random.h"

extern Random *randomObj;

AFUtils::AFUtils() {

}

static void XORblock(const unsigned char *src1, const unsigned char *src2, unsigned char *dst, size_t n) {
    size_t j;

    for (j = 0; j < n; j++)
        dst[j] = src1[j] ^ src2[j];
}

static int hashBuf(const unsigned char *src, unsigned char *dst, uint32_t iv, size_t len, const char *hash_name) {
    HashFunction *hf = new HashFunction();
    const unsigned char *iv_char = (const unsigned char *) &iv;
    int r;

    iv = be32_to_cpu(iv);
    if (hf->init(hash_name)) {
        r = -EINVAL;
        goto out;
    }

    if ((r = hf->write(iv_char, sizeof(uint32_t))))
        goto out;

    if ((r = hf->write(src, len)))
        goto out;

    r = hf->final(dst, len);
    out:
    delete hf;
    return r;
}

/*
 * diffuse: Information spreading over the whole dataset with
 * the help of hash function.
 */
static int diffuse(const unsigned char *src, unsigned char *dst, size_t size, const char *hashName) {

    int r, hash_size = HashFunction::hashSize(hashName);
    unsigned int digest_size;
    unsigned int i, blocks, padding;

    if (hash_size <= 0)
        return -EINVAL;
    digest_size = hash_size;

    blocks = size / digest_size;
    padding = size % digest_size;


    for (i = 0; i < blocks; i++) {
        r = hashBuf(src + digest_size * i,
                    dst + digest_size * i,
                    i, (size_t) digest_size, hashName);
        if (r < 0)
            return r;
    }

    if (padding) {
        r = hashBuf(src + digest_size * i,
                    dst + digest_size * i,
                    i, (size_t) padding, hashName);
        if (r < 0)
            return r;
    }


    return 0;
}

int AFUtils::split(const unsigned char *src, unsigned char *dst, size_t blocksize, unsigned int blocknumbers,
                   const char *hash) {
    unsigned int i;
    unsigned char *bufblock;
    int r;

    bufblock = (unsigned char *) Utils::safeAlloc(blocksize);
    if (!bufblock)
        return -ENOMEM;

    /* process everything except the last block */
    for (i = 0; i < blocknumbers - 1; i++) {
        r = randomObj->getRandom(dst + blocksize * i, blocksize);
        if (r < 0)
            goto out;

        XORblock(dst + blocksize * i, bufblock, bufblock, blocksize);
        r = diffuse(bufblock, bufblock, blocksize, hash);
        if (r < 0)
            goto out;
    }
    /* the last block is computed */
    XORblock(src, bufblock, dst + blocksize * i, blocksize);
    r = 0;
    out:
    Utils::safeFree(bufblock);
    return r;
}

int AFUtils::merge(const unsigned char *src, unsigned char *dst, size_t blocksize, unsigned int blocknumbers,
                   const char *hash) {

    unsigned int i;
    unsigned char *blockBuffer;
    int r;


    blockBuffer = (unsigned char *) Utils::safeAlloc(blocksize);
    if (!blockBuffer)
        return -ENOMEM;

    for (i = 0; i < blocknumbers - 1; i++) {
        XORblock(src + blocksize * i, blockBuffer, blockBuffer, blocksize);
        r = diffuse(blockBuffer, blockBuffer, blocksize, hash);
        if (r < 0)
            goto out;
    }
    XORblock(src + blocksize * i, blockBuffer, dst, blocksize);
    r = 0;
    out:
    Utils::safeFree(blockBuffer);
    return r;
}

size_t AFUtils::splitSectors(size_t blocksize, unsigned int blocknumbers) {
    size_t afSize;

    /* data material * stripes */
    afSize = blocksize * blocknumbers;

    /* round up to sector */
    afSize = (afSize + (SECTOR_SIZE - 1)) / SECTOR_SIZE;

    return afSize;
}
