#pragma once
#ifndef PBKDF_H
#define PBKDF_H
/** Iteration time set by crypt_set_iteration_time(), for compatibility only. */
#define CRYPT_PBKDF_ITER_TIME_SET   (1 << 0)
/** Never run benchmarks, use pre-set value or defaults. */
#define CRYPT_PBKDF_NO_BENCHMARK    (1 << 1)


#include <sys/types.h>
#include <unistd.h>
#include <ctype.h>
#include <inttypes.h>

#include "logger.h"
#include "luksdevice.h"

struct PbkdfLimits {
    uint32_t min_iterations, max_iterations;
    uint32_t min_memory, max_memory;
    uint32_t min_parallel, max_parallel;
};


static int parsePbkdf(const char *s, const char **pbkdf);
//static uint32_t adjusted_phys_memory(void)
static uint32_t adjustedPhysMemory(void);

/*
     * PBKDF configuration interface
     */
//int verify_pbkdf_params(LuksDevice *device,
int verifyPbkdfParams(LuksDevice *device, const struct PbkdfType *pbkdf);
//init_pbkdf_type
int initPbkdfType(LuksDevice *device,const struct PbkdfType *pbkdf,const char *dev_type);
//crypt_set_pbkdf_type
int setPbkdfType(LuksDevice *device, const struct PbkdfType *pbkdf);
//crypt_get_pbkdf_default
const struct PbkdfType *getPbkdfDefault(const char *type);
//crypt_set_iteration_time
void setIterationTime(LuksDevice *device, uint64_t iteration_time_ms);
int setPbkdfParams(LuksDevice *device, const char *devType);

#endif // PBKDF_H
