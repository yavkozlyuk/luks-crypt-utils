#include "key.h"
#include <termios.h>
#include "ioutils.h"
#include "logger.h"
#include <iomanip>
#include "utils.h"

extern Logger *logger;

Key::Key() {

}

Key::Key(size_t size, const char *key) {
    if (size > (SIZE_MAX - sizeof(*this)))
        throw std::invalid_argument("given keylength is too large");
    this->key = (unsigned char *) Utils::safeAlloc(size);
    this->keySize = size;
    /* keylength 0 is valid => no key */
    if (this->keySize) {
        if (key)
            memcpy(&this->key, key, size);
        else
            Utils::safeMemzero(this->key, size);
    }

}

Key::Key(Key &obj) {
    this->key = (unsigned char *) Utils::safeAlloc(obj.keySize);
    this->keySize = obj.getKeySize();
    /* keylength 0 is valid => no key */
    if (this->keySize) {
        if (obj.key)
            memcpy(this->key, obj.key, obj.keySize);
        else
            Utils::safeMemzero(this->key, obj.keySize);
    }
}

Key::~Key() {
    if (this->key)
        Utils::safeFree(this->key);
}

int Key::readKey(const char *file, size_t keysize) {
    int fd;
    this->keySize = keysize;
    this->key = (unsigned char *) Utils::safeAlloc(keysize);
    if (!this->key)
        return -ENOMEM;
    fd = open(file, O_RDONLY);
    if (fd == -1) {
        Logger::error("Cannot read keyfile %s.", file);
        goto fail;
    }
    if ((read(fd, key, keysize) != keysize)) {
        Logger::error("Cannot read %d bytes from keyfile %s.", keysize, file);
        close(fd);
        goto fail;
    }
    close(fd);
    return 0;
    fail:
    Utils::safeFree(key);
    key = NULL;
    return -EINVAL;
}

/* Password reading helpers */
static int untimed_read(int fd, char *pass, size_t maxlen) {
    ssize_t i;

    i = read(fd, pass, maxlen);
    if (i > 0) {
        pass[i - 1] = '\0';
        i = 0;
    } else if (i == 0) { /* EOF */
        *pass = 0;
        i = -1;
    }
    return i;
}

static int timed_read(int fd, char *pass, size_t maxlen, long timeout) {
    struct timeval t;
    fd_set fds = {}; /* Just to avoid scan-build false report for FD_SET */
    int failed = -1;

    FD_ZERO(&fds);
    FD_SET(fd, &fds);
    t.tv_sec = timeout;
    t.tv_usec = 0;

    if (select(fd + 1, &fds, NULL, NULL, &t) > 0)
        failed = untimed_read(fd, pass, maxlen);

    return failed;
}

static int interactive_pass(const char *prompt, char *pass, size_t maxlen,
                            long timeout) {
    struct termios orig, tmp;
    int failed = -1;
    int infd, outfd;

    if (maxlen < 1)
        return failed;

    /* Read and write to /dev/tty if available */
    infd = open("/dev/tty", O_RDWR);
    if (infd == -1) {
        infd = STDIN_FILENO;
        outfd = STDERR_FILENO;
    } else
        outfd = infd;

    if (tcgetattr(infd, &orig))
        goto out_err;

    memcpy(&tmp, &orig, sizeof(tmp));
    tmp.c_lflag &= ~ECHO;

    if (prompt && write(outfd, prompt, strlen(prompt)) < 0)
        goto out_err;

    tcsetattr(infd, TCSAFLUSH, &tmp);
    if (timeout)
        failed = timed_read(infd, pass, maxlen, timeout);
    else
        failed = untimed_read(infd, pass, maxlen);
    tcsetattr(infd, TCSAFLUSH, &orig);

    out_err:
    void *tp2 = malloc(10900);
    free(tp2);
    if (!failed && write(outfd, "\n", 1)) {};

    if (infd != STDIN_FILENO)
        close(infd);
    return failed;
}

int Key::readKeyTty(const char *prompt, int timeout, int verify) {
    int key_size_max = DEFAULT_PASSPHRASE_SIZE_MAX;
    int r = -EINVAL;
    char *pass = NULL, *pass_verify = NULL;

    this->key = NULL;
    this->keySize = 0;


    Logger::debug("Interactive passphrase entry requested.");

    pass = (char *) Utils::safeAlloc(key_size_max + 1);
    if (!pass) {
        Logger::error("Out of memory while reading passphrase.");
        return -ENOMEM;
    }

    if (interactive_pass(prompt, pass, key_size_max, timeout)) {
        Logger::error("Error reading passphrase from terminal.");
        goto out_err;
    }

    pass[key_size_max] = '\0';

    if (verify) {
        pass_verify = (char *) Utils::safeAlloc(key_size_max);
        if (!pass_verify) {
            Logger::error("Out of memory while reading passphrase.");
            r = -ENOMEM;
            goto out_err;
        }

        if (interactive_pass("Verify passphrase: ", pass_verify, key_size_max, timeout)) {
            Logger::error("Error reading passphrase from terminal.");
            goto out_err;
        }

        if (strncmp(pass, pass_verify, key_size_max)) {
            Logger::error("Passphrases do not match.");
            r = -EPERM;
            goto out_err;
        }
    }

    this->key = (unsigned char *) pass;
    this->keySize = strlen(pass);
    r = 0;
    out_err:
    Utils::safeFree(pass_verify);
    if (r)
        Utils::safeFree(pass);
    return r;
}

static int keyfileSeek(int fd, uint64_t bytes) {
    char tmp[BUFSIZ];
    size_t next_read;
    ssize_t bytes_r;
    off64_t r;

    r = lseek64(fd, bytes, SEEK_CUR);
    if (r > 0)
        return 0;
    if (r < 0 && errno != ESPIPE)
        return -1;

    while (bytes > 0) {
        /* figure out how much to read */
        next_read = bytes > sizeof(tmp) ? sizeof(tmp) : (size_t) bytes;

        bytes_r = read(fd, tmp, next_read);
        if (bytes_r < 0) {
            if (errno == EINTR)
                continue;

            Utils::memzero(tmp, sizeof(tmp));
            /* read error */
            return -1;
        }

        if (bytes_r == 0)
            /* EOF */
            break;

        bytes -= bytes_r;
    }

    Utils::memzero(tmp, sizeof(tmp));
    return bytes == 0 ? 0 : -1;
}

//crypt_keyfile_device_read
int Key::readKeyFromFile(const char *keyfile, uint64_t keyfile_offset, size_t key_size) {
    int fd, regular_file, char_to_read = 0, char_read = 0, unlimited_read = 0;
    int r = -EINVAL, newline;
    char *pass = NULL;
    size_t buflen, i;
    uint64_t file_read_size;
    struct stat st;

    if (!this->key || !this->keySize)
        return -EINVAL;

    this->key = NULL;
    this->keySize = 0;

    fd = keyfile ? open(keyfile, O_RDONLY) : STDIN_FILENO;
    if (fd < 0) {
        Logger::error("Failed to open key file.");
        return -EINVAL;
    }

    if (isatty(fd)) {
        Logger::error("Cannot read keyfile from a terminal.");
        r = -EINVAL;
        goto out_err;
    }

    /* If not requested otherwise, we limit input to prevent memory exhaustion */
    if (key_size == 0) {
        key_size = DEFAULT_KEYFILE_SIZE_MAXKB * 1024 + 1;
        unlimited_read = 1;
        /* use 4k for buffer (page divisor but avoid huge pages) */
        buflen = 4096 - sizeof(struct safeAllocation);
    } else
        buflen = key_size;

    regular_file = 0;
    if (keyfile) {
        if (stat(keyfile, &st) < 0) {
            Logger::error("Failed to stat key file.");
            goto out_err;
        }
        if (S_ISREG(st.st_mode)) {
            regular_file = 1;
            file_read_size = (uint64_t) st.st_size;

            if (keyfile_offset > file_read_size) {
                Logger::error("Cannot seek to requested keyfile offset.");
                goto out_err;
            }
            file_read_size -= keyfile_offset;

            /* known keyfile size, alloc it in one step */
            if (file_read_size >= (uint64_t) key_size)
                buflen = key_size;
            else if (file_read_size)
                buflen = file_read_size;
        }
    }

    pass = (char *) Utils::safeAlloc(buflen);
    if (!pass) {
        Logger::error("Out of memory while reading passphrase.");
        goto out_err;
    }

    /* Discard keyfile_offset bytes on input */
    if (keyfile_offset && keyfileSeek(fd, keyfile_offset) < 0) {
        Logger::error("Cannot seek to requested keyfile offset.");
        goto out_err;
    }

    for (i = 0, newline = 0; i < key_size; i += char_read) {
        if (i == buflen) {
            buflen += 4096;
            pass = (char *) Utils::safeRealloc(pass, buflen);
            if (!pass) {
                Logger::error("Out of memory while reading passphrase.");
                r = -ENOMEM;
                goto out_err;
            }
        }

        if (CRYPT_KEYFILE_STOP_EOL) {
            /* If we should stop on newline, we must read the input
                 * one character at the time. Otherwise we might end up
                 * having read some bytes after the newline, which we
                 * promised not to do.
                 */
            char_to_read = 1;
        } else {
            /* char_to_read = min(key_size - i, buflen - i) */
            char_to_read = key_size < buflen ?
                           key_size - i : buflen - i;
        }
        char_read = IOUtils::readBuffer(fd, &pass[i], char_to_read);
        if (char_read < 0) {
            Logger::error("Error reading passphrase.");
            r = -EPIPE;
            goto out_err;
        }

        if (char_read == 0)
            break;
        /* Stop on newline only if not requested read from keyfile */
        if ((CRYPT_KEYFILE_STOP_EOL) && pass[i] == '\n') {
            newline = 1;
            pass[i] = '\0';
            break;
        }
    }

    /* Fail if piped input dies reading nothing */
    if (!i && !regular_file && !newline) {
        Logger::error("Nothing to read on input.");
        r = -EPIPE;
        goto out_err;
    }

    /* Fail if we exceeded internal default (no specified size) */
    if (unlimited_read && i == key_size) {
        Logger::error("Maximum keyfile size exceeded.");
        goto out_err;
    }

    if (!unlimited_read && i != key_size) {
        Logger::error("Cannot read requested amount of data.");
        goto out_err;
    }

    this->key = (unsigned char *) pass;
    this->keySize = i;
    r = 0;
    out_err:
    if (fd != STDIN_FILENO)
        close(fd);

    if (r)
        Utils::safeFree(pass);
    return r;
}

int
Key::readKey(const char *prompt, uint64_t keyfile_offset, size_t keyfile_size_max, const char *key_file, int timeout,
             int verify, int pwquality, const char *devicePath) {
    char tmp[1024];
    int r = -EINVAL, block;
    if (Utils::isStdin(key_file)) {
        if (keyfile_offset) {
            throw std::invalid_argument("Cannot use offset with terminal input.");
        } else {
            if (!prompt && !devicePath)
                snprintf(tmp, sizeof(tmp), "Enter passphrase: ");
            else if (!prompt)
                snprintf(tmp, sizeof(tmp), "Enter passphrase for %s: ", devicePath);
            r = readKeyTty(prompt ?: tmp, timeout, verify);
        }

    } else {
        Logger::debug("File descriptor passphrase entry requested.");
        r = readKeyFromFile(key_file, keyfile_offset, keyfile_size_max);
    }

    return r;
}

size_t Key::getKeySize() const {
    return keySize;
}

void Key::setKeySize(const size_t &value) {
    keySize = value;
}

unsigned char *Key::getKey() const {
    return key;
}

void Key::setKey(unsigned char *value) {
    key = value;
}

int Key::writeKey(const char *file) {
    int fd, r = -EINVAL;

    fd = open(file, O_CREAT | O_EXCL | O_WRONLY, S_IRUSR);
    if (fd < 0) {
        Logger::error("Cannot open keyfile %s for write.", file);
        return r;
    }

    if (IOUtils::writeBuffer(fd, key, keySize) == keySize)
        r = 0;
    else
        Logger::error("Cannot write to keyfile %s.", file);

    close(fd);
    return r;
}


std::ostream &operator<<(std::ostream &os, const Key &key) {
    std::cout << "MK dump:\t";
    std::ios state(nullptr);
    state.copyfmt(std::cout);
    for (int i = 0; i < key.getKeySize(); i++) {
        if (i && !(i % 16))
            std::cout << ("\n\t\t");
        std::cout << std::hex << std::setfill('0') << std::setw(2) << (int) (unsigned char) key.getKey()[i] << " ";
    }
    std::cout.copyfmt(state);
    std::cout << std::endl;
    return os;
}
