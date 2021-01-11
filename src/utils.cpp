#include "utils.h"
#include "bitops.h"
#include "luksconstants.h"
#include "opensslcryptoprovider.h"
#include "logger.h"

#include <unistd.h>
#include <sys/utsname.h>
#include <limits.h>

/* interrupt handling */
volatile int quit = 0;

extern const char *opt_header_device;
extern const char *opt_device;
extern const char *action_argv[];
/* safe allocations */
/*
 * Replacement for memset(s, 0, n) on stack that can be optimized out
 * Also used in safe allocations for explicit memory wipe.
 */
void Utils::memzero(void *s, size_t n) {
#ifdef HAVE_EXPLICIT_BZERO
    explicit_bzero(s, n);
#else
    volatile uint8_t *p = (volatile uint8_t *) s;

    while (n--)
        *p++ = 0;
#endif
}

void Utils::safeMemzero(void *data, size_t size) {
#ifdef HAVE_EXPLICIT_BZERO
    explicit_bzero(data, size);
#else
    volatile uint8_t *p = (volatile uint8_t *) data;

    while (size--)
        *p++ = 0;
#endif
}

void *Utils::safeAlloc(size_t size) {
    struct safeAllocation *alloc;

    if (!size || size > (SIZE_MAX - offsetof(struct safeAllocation, data)))
        return NULL;
    alloc = (safeAllocation *) std::malloc(size + offsetof(struct safeAllocation, data));
    if (!alloc)
        return NULL;

    alloc->size = size;
    Utils::safeMemzero(&alloc->data, size);

    /* coverity[leaked_storage] */
    return &alloc->data;
}

void *Utils::safeRealloc(void *data, size_t size) {
    struct safeAllocation *alloc;
    void *new_data;

    new_data = Utils::safeAlloc(size);

    if (new_data && data) {

        alloc = (struct safeAllocation *) ((char *) data - offsetof(struct safeAllocation, data));

        if (size > alloc->size)
            size = alloc->size;

        memcpy(new_data, data, size);
    }

    safeFree(data);
    return new_data;
}

void Utils::safeFree(void *data) {
    struct safeAllocation *alloc;

    if (!data)
        return;

    alloc = (struct safeAllocation *) ((char *) data - offsetof(struct safeAllocation, data));

    Utils::safeMemzero(data, alloc->size);

    alloc->size = 0x55aa55aa;
    if (alloc)
        free(alloc);
}

//uuid
const char *Utils::uuidOrDeviceHeader(const char **data_device) {
    if (data_device)
        *data_device = opt_header_device ? opt_device : NULL;

    return uuidOrDevice(opt_header_device ?: opt_device);
}

const char *Utils::uuidOrDevice(const char *spec) {
    static char device[PATH_MAX];
    char s, *ptr;
    int i = 0, uuid_len = 5;

    /* Check if it is correct UUID=<LUKS_UUID> format */
    if (spec && !strncmp(spec, "UUID=", uuid_len)) {
        strcpy(device, "/dev/disk/by-uuid/");
        ptr = &device[strlen(device)];
        i = uuid_len;
        while ((s = spec[i++]) && i < (PATH_MAX - 13)) {
            if (!isxdigit(s) && s != '-')
                return spec; /* Bail it out */
            if (isalpha(s))
                s = tolower(s);
            *ptr++ = s;
        }
        *ptr = '\0';
        return device;
    }

    return spec;
}


//console  output
void Utils::coutHexStr(const char *str, size_t length) {
    std::ios state(nullptr);
    state.copyfmt(std::cout);
    for (size_t i = 0; i < length; ++i) {
        if (i && !(i % 16))
            std::cout << std::endl << "\t\t";
        std::cout << std::hex << std::setfill('0') << std::setw(2) << (int) (unsigned char) str[i] << " ";
    }
    std::cout.copyfmt(state);
    std::cout << std::endl;
}

void Utils::coutHexStr(const char *caption, const char *str, size_t length) {
    std::cout << caption << ": ";
    coutHexStr(str, length);
}

/*
 * Keyfile - is standard input treated as a binary file (no EOL handling).
 */
int Utils::isStdin(const char *key_file) {
    if (!key_file)
        return 1;

    return strcmp(key_file, "-") ? 0 : 1;
}

int Utils::isLUKS1(const char *type) {
    return (type && !strcmp(CRYPT_LUKS1, type));
}

size_t Utils::getPageSize(void) {
    long r = sysconf(_SC_PAGESIZE);
    return r <= 0 ? DEFAULT_MEM_ALIGNMENT : (size_t) r;
}

int Utils::intLog2(unsigned int x) {
    int r = 0;
    for (x >>= 1; x > 0; x >>= 1)
        r++;
    return r;
}


void Utils::checkSignal(int *r) {
    if (quit && !*r)
        *r = -EINTR;
}

void Utils::checkMemory(size_t s) {
    void *tmp = malloc(s);
    free(tmp);
}

int Utils::translateErrorCode(int r) {
    switch (r) {
        case 0:
            r = EXIT_SUCCESS;
            break;
        case -EEXIST:
        case -EBUSY:
            r = 5;
            break;
        case -ENOTBLK:
        case -ENODEV:
            r = 4;
            break;
        case -ENOMEM:
            r = 3;
            break;
        case -EPERM:
            r = 2;
            break;
        case -EINVAL:
        case -ENOENT:
        case -ENOSYS:
        default:
            r = EXIT_FAILURE;
    }
    return r;
}

int Utils::parseCipherNameAndMode(const char *s, char *cipher, int *keyNums, char *cipherMode) {
    if (!s || !cipher || !cipherMode)
        return -EINVAL;

    if (sscanf(s, "%" MAX_CIPHER_LEN_STR "[^-]-%" MAX_CIPHER_LEN_STR "s",
               cipher, cipherMode) == 2) {
        if (!strcmp(cipherMode, "plain"))
            strcpy(cipherMode, "cbc-plain");
        if (keyNums) {
            char *tmp = strchr(cipher, ':');
            *keyNums = tmp ? atoi(++tmp) : 1;
            if (!*keyNums)
                return -EINVAL;
        }

        return 0;
    }

    /* Short version for "empty" cipher */
    if (!strcmp(s, "null") || !strcmp(s, "cipher_null")) {
        strcpy(cipher, "cipher_null");
        strcpy(cipherMode, "ecb");
        if (keyNums)
            *keyNums = 0;
        return 0;
    }

    if (sscanf(s, "%" MAX_CIPHER_LEN_STR "[^-]", cipher) == 1) {
        strcpy(cipherMode, "cbc-plain");
        if (keyNums)
            *keyNums = 1;
        return 0;
    }

    return -EINVAL;
}

int Utils::initCrypto() {
    struct utsname uts;
    int r;

    if (r < 0)
        Logger::error("Cannot initialize crypto backend.");

    if (!r) {
        const char *version = OpenSSLCryptoProvider::getOpenSSLVersion();

        Logger::debug("Crypto backend (%s) initialized in cryptsetup library version %s.", version, PACKAGE_VERSION);
        if (!uname(&uts))
            Logger::debug("Detected kernel %s %s %s.", uts.sysname, uts.release, uts.machine);
    }

    return r;
}

uint64_t Utils::getPhysmemoryKb() {
    long pagesize, phys_pages;
    uint64_t phys_memory_kb;

    pagesize = sysconf(_SC_PAGESIZE);
    phys_pages = sysconf(_SC_PHYS_PAGES);

    if (pagesize < 0 || phys_pages < 0)
        return 0;

    phys_memory_kb = pagesize / 1024;
    phys_memory_kb *= phys_pages;

    return phys_memory_kb;
}

unsigned Utils::cpusOnline() {
    long r = sysconf(_SC_NPROCESSORS_ONLN);
    return r < 0 ? 1 : r;
}

size_t Utils::sizeRoundUp(size_t size, size_t block) {
    size_t s = (size + (block - 1)) / block;
    return s * block;
}

void Utils::_toLower(char *str, unsigned max_len) {
    for (; *str && max_len; str++, max_len--)
        if (isupper(*str))
            *str = tolower(*str);
}

int Utils::confirmDialog(const char *msg, const char *failMsg) {
    char *answer = NULL;
    size_t size = 0;
    int r = 1;


    if (isatty(STDIN_FILENO)) {
        Logger::info("\nWARNING!\n========\n");
        Logger::info("%s\n\nAre you sure? (Type uppercase yes): ", msg);
        fflush(stdout);
        if(getline(&answer, &size, stdin) == -1) {
            r = 0;
            Logger::error("Error reading response from terminal.");
        } else if (strcmp(answer, "YES\n")) {
            r = 0;
            if (failMsg)
                Logger::error("%s", failMsg);
        }
    }

    free(answer);
    return r;
}

