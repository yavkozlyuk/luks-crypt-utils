#include "pbkdf.h"
#include "luksconstants.h"
#include "utils.h"
#include "hashfunction.h"


extern const char *opt_pbkdf;
extern const char *opt_hash;
extern long opt_pbkdf_memory;
extern long opt_pbkdf_parallel;
extern long opt_pbkdf_iterations;
extern int opt_iteration_time;

extern struct PbkdfType defaultLuks1;

/* These PBKDF2 limits must be never violated */
static int pbkdfGetLimits(const char *kdf, struct PbkdfLimits *limits) {
    if (!kdf || !limits)
        return -EINVAL;

    if (!strcmp(kdf, "pbkdf2")) {
        limits->min_iterations = 1000; /* recommendation in NIST SP 800-132 */
        limits->max_iterations = UINT32_MAX;
        limits->min_memory = 0; /* N/A */
        limits->max_memory = 0; /* N/A */
        limits->min_parallel = 0; /* N/A */
        limits->max_parallel = 0; /* N/A */
        return 0;
    } else if (!strcmp(kdf, "argon2i") || !strcmp(kdf, "argon2id")) {
        limits->min_iterations = 4;
        limits->max_iterations = UINT32_MAX;
        limits->min_memory = 32;
        limits->max_memory = 4 * 1024 * 1024; /* 4GiB */
        limits->min_parallel = 1;
        limits->max_parallel = 4;
        return 0;
    }

    return -EINVAL;
}

int parsePbkdf(const char *s, const char **pbkdf) {
    const char *tmp = NULL;

    if (!s)
        return -EINVAL;

    if (!strcasecmp(s, CRYPT_KDF_PBKDF2))
        tmp = CRYPT_KDF_PBKDF2;
    else if (!strcasecmp(s, CRYPT_KDF_ARGON2I))
        tmp = CRYPT_KDF_ARGON2I;
    else if (!strcasecmp(s, CRYPT_KDF_ARGON2ID))
        tmp = CRYPT_KDF_ARGON2ID;

    if (!tmp)
        return -EINVAL;

    if (pbkdf)
        *pbkdf = tmp;

    return 0;
}

uint32_t adjustedPhysMemory() {
    uint64_t memory_kb = Utils::getPhysmemoryKb();

    /* Ignore bogus value */
    if (memory_kb < (128 * 1024) || memory_kb > UINT32_MAX)
        return DEFAULT_LUKS2_MEMORY_KB;

    /*
     * Never use more than half of physical memory.
     * OOM killer is too clever...
     */
    memory_kb /= 2;

    return memory_kb;
}

int verifyPbkdfParams(LuksDevice *device, const struct PbkdfType *pbkdf) {
    struct PbkdfLimits pbkdfLimits;
    const char *pbkdf_type;
    int r;

    r = Utils::initCrypto();
    if (r < 0)
        return r;

    if (!pbkdf->type ||
        (!pbkdf->hash && !strcmp(pbkdf->type, "pbkdf2")))
        return -EINVAL;

    if (!pbkdf->timeMs && !(pbkdf->flags & CRYPT_PBKDF_NO_BENCHMARK)) {
        Logger::error("Requested PBKDF target time cannot be zero.");
        return -EINVAL;
    }

    r = parsePbkdf(pbkdf->type, &pbkdf_type);
    if (r < 0) {
        Logger::error("Unknown PBKDF type %s.", pbkdf->type);
        return r;
    }

    if (pbkdf->hash && HashFunction::hashSize(pbkdf->hash) < 0) {
        Logger::error("Requested hash %s is not supported.", pbkdf->hash);
        return -EINVAL;
    }

    r = pbkdfGetLimits(pbkdf->type, &pbkdfLimits);
    if (r < 0)
        return r;

    if (device->getPath() && !strcmp(device->getPath(), CRYPT_LUKS1) && strcmp(pbkdf_type, CRYPT_KDF_PBKDF2)) {
        Logger::error("Requested PBKDF type is not supported for LUKS1.");
        return -EINVAL;
    }

    if (!strcmp(pbkdf_type, CRYPT_KDF_PBKDF2)) {
        if (pbkdf->maxMemoryKb || pbkdf->parallelThreads) {
            Logger::error("PBKDF max memory or parallel threads must not be set with pbkdf2.");
            return -EINVAL;
        }
        if (pbkdf->flags & CRYPT_PBKDF_NO_BENCHMARK &&
            pbkdf->iterations < pbkdfLimits.min_iterations) {
            Logger::error("Forced iteration count is too low for %s (minimum is %u).", pbkdf_type,
                          pbkdfLimits.min_iterations);
            return -EINVAL;
        }
        return 0;
    }

    /* TODO: properly define minimal iterations and also minimal memory values */
    if (pbkdf->flags & CRYPT_PBKDF_NO_BENCHMARK) {
        if (pbkdf->iterations < pbkdfLimits.min_iterations) {
            Logger::error("Forced iteration count is too low for %s (minimum is %u).",
                          pbkdf_type, pbkdfLimits.min_iterations);
            r = -EINVAL;
        }
        if (pbkdf->maxMemoryKb < pbkdfLimits.min_memory) {
            Logger::error("Forced memory cost is too low for %s (minimum is %u kilobytes).",
                          pbkdf_type, pbkdfLimits.min_memory);
            r = -EINVAL;
        }
    }

    if (pbkdf->maxMemoryKb > pbkdfLimits.max_memory) {
        Logger::error("Requested maximum PBKDF memory cost is too high (maximum is %d kilobytes).",
                      pbkdfLimits.max_memory);
        r = -EINVAL;
    }
    if (!pbkdf->maxMemoryKb) {
        Logger::error("Requested maximum PBKDF memory cannot be zero.");
        r = -EINVAL;
    }
    if (!pbkdf->parallelThreads) {
        Logger::error("Requested PBKDF parallel threads cannot be zero.");
        r = -EINVAL;
    }

    return r;
}

int initPbkdfType(LuksDevice *device, const PbkdfType *pbkdf, const char *devType) {
    struct PbkdfType *cd_pbkdf = device->getPbkdf();
    struct PbkdfLimits pbkdfLimits;
    const char *hash, *type;
    unsigned cpus;
    uint32_t old_flags, memory_kb;
    int r;

    if (!pbkdf)
        pbkdf = &defaultLuks1;

    r = verifyPbkdfParams(device, pbkdf);
    if (r)
        return r;

    r = pbkdfGetLimits(pbkdf->type, &pbkdfLimits);
    if (r < 0)
        return r;

    type = strdup(pbkdf->type);
    hash = pbkdf->hash ? strdup(pbkdf->hash) : NULL;

    if (!type || (!hash && pbkdf->hash)) {
        free(CONST_CAST(void*) type);
        free(CONST_CAST(void*) hash);
        return -ENOMEM;
    }
    //if (cd_pbkdf->type)
    //    free(CONST_CAST(void*) cd_pbkdf->type);
    free(CONST_CAST(void*) cd_pbkdf->hash);
    cd_pbkdf->type = (char *) type;
    cd_pbkdf->hash = (char *) hash;

    old_flags = cd_pbkdf->flags;
    cd_pbkdf->flags = pbkdf->flags;

    /* Reset iteration count so benchmark must run again. */
    if (cd_pbkdf->flags & CRYPT_PBKDF_NO_BENCHMARK)
        cd_pbkdf->iterations = pbkdf->iterations;
    else
        cd_pbkdf->iterations = 0;

    if (old_flags & CRYPT_PBKDF_ITER_TIME_SET)
        cd_pbkdf->flags |= CRYPT_PBKDF_ITER_TIME_SET;
    else
        cd_pbkdf->timeMs = pbkdf->timeMs;

    cd_pbkdf->maxMemoryKb = pbkdf->maxMemoryKb;
    cd_pbkdf->parallelThreads = pbkdf->parallelThreads;

    if (cd_pbkdf->parallelThreads > pbkdfLimits.max_parallel) {
        Logger::debug("Maximum PBKDF threads is %d (requested %d).", pbkdfLimits.max_parallel,
                      cd_pbkdf->parallelThreads);
        cd_pbkdf->parallelThreads = pbkdfLimits.max_parallel;
    }

    if (cd_pbkdf->parallelThreads) {
        cpus = Utils::cpusOnline();
        if (cd_pbkdf->parallelThreads > cpus) {
            Logger::debug("Only %u active CPUs detected, "
                          "PBKDF threads decreased from %d to %d.",
                          cpus, cd_pbkdf->parallelThreads, cpus);
            cd_pbkdf->parallelThreads = cpus;
        }
    }

    if (cd_pbkdf->maxMemoryKb) {
        memory_kb = adjustedPhysMemory();
        if (cd_pbkdf->maxMemoryKb > memory_kb) {
            Logger::debug("Not enough physical memory detected, "
                          "PBKDF max memory decreased from %dkB to %dkB.",
                          cd_pbkdf->maxMemoryKb, memory_kb);
            cd_pbkdf->maxMemoryKb = memory_kb;
        }
    }

    Logger::debug("PBKDF %s, hash %s, timeMs %u (iterations %u), maxMemoryKb %u, parallelThreads %u.",
                  cd_pbkdf->type ?: "(none)", cd_pbkdf->hash ?: "(none)", cd_pbkdf->timeMs,
                  cd_pbkdf->iterations, cd_pbkdf->maxMemoryKb, cd_pbkdf->parallelThreads);

    return 0;
}

int setPbkdfType(LuksDevice *device, const PbkdfType *pbkdf) {
    if (!device)
        return -EINVAL;

    if (!pbkdf)
        Logger::debug("Resetting pbkdf type to default");


    device->setPbkdfFlags(0);

    return initPbkdfType(device, pbkdf, device->getType());
}

const PbkdfType *getPbkdfDefault(const char *type) {
    if (!type)
        return NULL;

    if (!strcmp(type, CRYPT_LUKS1))
        return &defaultLuks1;

    return NULL;
}

void setIterationTime(LuksDevice *device, uint64_t iteration_timeMs) {
    struct PbkdfType *pbkdf;
    uint32_t old_timeMs;

    if (!device || iteration_timeMs > UINT32_MAX)
        return;

    pbkdf = device->getPbkdf();
    old_timeMs = pbkdf->timeMs;
    pbkdf->timeMs = (uint32_t) iteration_timeMs;

    if (pbkdf->type && verifyPbkdfParams(device, pbkdf)) {
        pbkdf->timeMs = old_timeMs;
        Logger::debug("Invalid iteration time.");
        return;
    }

    pbkdf->flags |= CRYPT_PBKDF_ITER_TIME_SET;

    /* iterations must be benchmarked now */
    pbkdf->flags &= ~(CRYPT_PBKDF_NO_BENCHMARK);
    pbkdf->iterations = 0;

    Logger::debug("Iteration time set to %" PRIu64 " milliseconds.", iteration_timeMs);
}

int setPbkdfParams(LuksDevice *device, const char *devType) {
    struct PbkdfType pbkdf = {};

    if (!strcmp(devType, CRYPT_LUKS1)) {
        if (opt_pbkdf && strcmp(opt_pbkdf, CRYPT_KDF_PBKDF2))
            return -EINVAL;
        pbkdf.type = (char *) CRYPT_KDF_PBKDF2;
        pbkdf.hash = (char *) (opt_hash ?: DEFAULT_LUKS1_HASH);
        pbkdf.timeMs = opt_iteration_time ?: DEFAULT_LUKS1_ITER_TIME;
    } else if (!strcmp(devType, CRYPT_LUKS2)) {
        pbkdf.type = (char *) (opt_pbkdf ?: DEFAULT_LUKS2_PBKDF);
        pbkdf.hash = (char *) (opt_hash ?: DEFAULT_LUKS1_HASH);
        pbkdf.timeMs = (opt_iteration_time ?: DEFAULT_LUKS2_ITER_TIME);
        if (strcmp(pbkdf.type, CRYPT_KDF_PBKDF2)) {
            pbkdf.maxMemoryKb = opt_pbkdf_memory;
            pbkdf.parallelThreads = opt_pbkdf_parallel;
        }
    } else
        return 0;

    if (opt_pbkdf_iterations) {
        pbkdf.iterations = opt_pbkdf_iterations;
        pbkdf.flags |= CRYPT_PBKDF_NO_BENCHMARK;
    }

    return setPbkdfType(device, &pbkdf);
}
