#pragma once
#ifndef UTILS_H
#define UTILS_H

#define CONST_CAST(x) (x)(uintptr_t)
#define at_least(a, b) ({ __typeof__(a) __at_least = (a); (__at_least >= (b))?__at_least:(b); })

#include <sys/types.h>
#include <inttypes.h>
#include <cstdlib>
#include <string.h>
#include <memory>
#include <iostream>
#include <iomanip>
#include "afutils.h"

struct safeAllocation {
    size_t size;
    char data[0];
};

/* Memzero helper (memset on stack can be optimized out) */
static inline void backendMemzero(void *s, size_t n) {
#ifdef HAVE_EXPLICIT_BZERO
    explicit_bzero(s, n);
#else
    volatile uint8_t *p = (volatile uint8_t*) s;
    while (n--)
        *p++ = 0;
#endif
}
class Utils {
public:
    Utils();
    static void memzero(void *s, size_t n);
    static void safeMemzero(void *data, size_t size);
    static void safeFree(void*);
    static void *safeAlloc(size_t);
    static void *safeRealloc(void *data, size_t size);
    static const char *uuidOrDevice(const char *spec);
    static void coutHexStr(const char* str, size_t length);
    static void coutHexStr(const char* caption, const char* str, size_t length);
    static const char *uuidOrDeviceHeader(const char **data_device);
    static int isStdin(const char *key_file);
    static int isLUKS1(const char* type);
    static size_t getPageSize(void);
    static int intLog2(unsigned int x);
    static void checkSignal(int *r);
    static void checkMemory(size_t s);
    /* Translate exit code to simple codes */
    static int translateErrorCode(int r);
    static int parseCipherNameAndMode(const char *s, char *cipher, int *keyNums, char *cipherMode);
    static int initCrypto();
    static uint64_t getPhysmemoryKb();
    static unsigned cpusOnline();
    static size_t sizeRoundUp(size_t size, size_t block);
    static void _toLower(char *str, unsigned max_len);
};



#endif // UTILS_H
