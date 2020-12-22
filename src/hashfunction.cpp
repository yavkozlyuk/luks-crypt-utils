#include "hashfunction.h"
#include "utils.h"
HashFunction::HashFunction() {

}

HashFunction::~HashFunction()
{
    if (this->md) {
        EVP_MD_CTX_free(this->md);
        this->md = NULL;
    }
}

int HashFunction::init(const char *name) {

    this->md = EVP_MD_CTX_new();
    if (!this->md) {
        return -ENOMEM;
    }

    this->hash_id = EVP_get_digestbyname(name);
    if (!this->hash_id) {
        EVP_MD_CTX_free(this->md);
        return -EINVAL;
    }

    if (EVP_DigestInit_ex(this->md, this->hash_id, NULL) != 1) {
        EVP_MD_CTX_free(this->md);
        return -EINVAL;
    }

    this->hash_len = EVP_MD_size(this->hash_id);
    return 0;
}

int HashFunction::write(const unsigned char *buffer, size_t length) {
    if (EVP_DigestUpdate(this->md, buffer, length) != 1)
        return -EINVAL;

    return 0;
}

int HashFunction::final(unsigned char *buffer, size_t length) {
    unsigned char tmp[EVP_MAX_MD_SIZE];
    unsigned int tmp_len = 0;

    if (length > (size_t) this->hash_len)
        return -EINVAL;

    if (EVP_DigestFinal_ex(this->md, tmp, &tmp_len) != 1)
        return -EINVAL;

    memcpy(buffer, tmp, length);
    backendMemzero(tmp, sizeof(tmp));

    if (tmp_len < length)
        return -EINVAL;

    if (hashRestart(this))
        return -EINVAL;

    return 0;

}

int HashFunction::hashSize(const char *name) {
    const EVP_MD *hash_id = EVP_get_digestbyname(name);

    if (!hash_id)
        return -EINVAL;

    return EVP_MD_size(hash_id);
}

int HashFunction::hashRestart(HashFunction *hashFunction) {
    if (EVP_DigestInit_ex(hashFunction->md, hashFunction->hash_id, NULL) != 1)
        return -EINVAL;

    return 0;
}
