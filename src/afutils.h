#pragma once
#ifndef AFUTILS_H
#define AFUTILS_H

#include <stddef.h>


class AFUtils {
public:
    AFUtils();

    static int
    split(const unsigned char *src, unsigned char *dst, size_t blocksize, unsigned int blocknumbers, const char *hash);

    static int
    merge(const unsigned char *src, unsigned char *dst, size_t blocksize, unsigned int blocknumbers, const char *hash);

    static size_t splitSectors(size_t blocksize, unsigned int blocknumbers);

};

#endif // AFUTILS_H
