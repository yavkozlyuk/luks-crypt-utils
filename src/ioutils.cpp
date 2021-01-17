#include "ioutils.h"

#include <errno.h>
#include <string.h>
#include <stdlib.h>
#include <cstdint>
#include <unistd.h>
#include <sys/types.h>

#include "utils.h"
IOUtils::IOUtils() {

}

static ssize_t _readBuffer(int fd, void *buf, size_t length, volatile int *quit) {
    size_t read_size = 0;
    ssize_t r;

    if (fd < 0 || !buf)
        return -EINVAL;

    do {
        r = read(fd, buf, length - read_size);
        if (r == -1 && errno != EINTR)
            return r;
        if (r > 0) {
            read_size += (size_t) r;
            buf = (uint8_t *) buf + r;
        }
        if (r == 0 || (quit && *quit))
            return (ssize_t) read_size;
    } while (read_size != length);

    return (ssize_t) length;
}

ssize_t IOUtils::readBuffer(int fd, void *buf, size_t length) {
    return _readBuffer(fd, buf, length, NULL);
}

ssize_t IOUtils::readBufferIntr(int fd, void *buf, size_t length, volatile int *quit) {
    return _readBuffer(fd, buf, length, quit);
}

static ssize_t _writeBuffer(int fd, const void *buf, size_t length, volatile int *quit) {
    size_t write_size = 0;
    ssize_t w;

    if (fd < 0 || !buf || !length)
        return -EINVAL;

    do {
        w = write(fd, buf, length - write_size);
        if (w < 0 && errno != EINTR)
            return w;
        if (w > 0) {
            write_size += (size_t) w;
            buf = (const uint8_t *) buf + w;
        }
        if (w == 0 || (quit && *quit))
            return (ssize_t) write_size;
    } while (write_size != length);

    return (ssize_t) write_size;
}

ssize_t IOUtils::writeBuffer(int fd, const void *buf, size_t length) {
    return _writeBuffer(fd, buf, length, NULL);
}

ssize_t IOUtils::writeBufferIntr(int fd, const void *buf, size_t length, volatile int *quit) {
    return _writeBuffer(fd, buf, length, quit);
}

ssize_t IOUtils::writeBlockwise(int fd, size_t bsize, size_t alignment, void *origBuf, size_t length) {
    void *hangoverBuf = NULL, *buf = NULL;
    size_t hangover, solid;
    ssize_t r, ret = -1;

    if (fd == -1 || !origBuf || !bsize || !alignment)
        return -1;

    hangover = length % bsize;
    solid = length - hangover;

    if ((size_t) origBuf & (alignment - 1)) {
        if (posix_memalign(&buf, alignment, length))
            return -1;
        memcpy(buf, origBuf, length);
    } else
        buf = origBuf;

    if (solid) {
        r = writeBuffer(fd, buf, solid);
        if (r < 0 || r != (ssize_t) solid)
            goto out;
    }

    if (hangover) {
        if (posix_memalign(&hangoverBuf, alignment, bsize))
            goto out;
        memset(hangoverBuf, 0, bsize);

        r = readBuffer(fd, hangoverBuf, bsize);
        if (r < 0)
            goto out;

        if (lseek(fd, -(off_t) r, SEEK_CUR) < 0)
            goto out;

        memcpy(hangoverBuf, (char *) buf + solid, hangover);

        r = writeBuffer(fd, hangoverBuf, bsize);
        if (r < 0 || r < (ssize_t) hangover)
            goto out;
    }
    ret = length;
out:
    free(hangoverBuf);
    if (buf != origBuf)
        free(buf);
    return ret;
}

ssize_t IOUtils::readBlockwise(int fd, size_t bsize, size_t alignment, void *origBuf, size_t length) {
    void *hangoverBuf = NULL, *buf = NULL;
    size_t hangover, solid;
    ssize_t r, ret = -1;

    if (fd == -1 || !origBuf || !bsize || !alignment)
        return -1;

    hangover = length % bsize;
    solid = length - hangover;

    if ((size_t) origBuf & (alignment - 1)) {
        if (posix_memalign(&buf, alignment, length))
            return -1;
    } else
        buf = origBuf;

    r = readBuffer(fd, buf, solid);
    if (r < 0 || r != (ssize_t) solid)
        goto out;


    if (hangover) {
        if (posix_memalign((void **) &hangoverBuf, alignment, bsize))
            goto out;

        r = readBuffer(fd, hangoverBuf, bsize);

        if (r < 0 || r < (ssize_t) hangover)
            goto out;


        memcpy((char *) buf + solid, hangoverBuf, hangover);
    }
    ret = length;
out:

    free(hangoverBuf);
    if (buf != origBuf) {
        if (ret != -1)
            memcpy(origBuf, buf, length);
        free(buf);
    }

    return ret;
}

ssize_t IOUtils::writeLseekBlockwise(int fd, size_t bsize, size_t alignment, void *buf, size_t length, off_t offset) {
    void *frontPadBuf = NULL;
    size_t frontHang, innerCount = 0;
    ssize_t r, ret = -1;

    if (fd == -1 || !buf || !bsize || !alignment)
        return -1;

    if (offset < 0)
        offset = lseek(fd, offset, SEEK_END);

    if (offset < 0)
        return -1;

    frontHang = offset % bsize;

    if (lseek(fd, offset - frontHang, SEEK_SET) < 0)
        return -1;

    if (frontHang && length) {
        if (posix_memalign(&frontPadBuf, alignment, bsize))
            return -1;

        innerCount = bsize - frontHang;
        if (innerCount > length)
            innerCount = length;

        r = readBuffer(fd, frontPadBuf, bsize);
        if (r < 0 || r < (ssize_t) (frontHang + innerCount))
            goto out;

        memcpy((char *) frontPadBuf + frontHang, buf, innerCount);

        if (lseek(fd, offset - frontHang, SEEK_SET) < 0)
            goto out;

        r = writeBuffer(fd, frontPadBuf, bsize);
        if (r < 0 || r != (ssize_t) bsize)
            goto out;

        buf = (char *) buf + innerCount;
        length -= innerCount;
    }

    ret = length ? writeBlockwise(fd, bsize, alignment, buf, length) : 0;
    if (ret >= 0)
        ret += innerCount;
out:
    free(frontPadBuf);
    return ret;
}

ssize_t IOUtils::readLseekBlockwise(int fd, size_t bsize, size_t alignment, void *buf, size_t length, off_t offset) {
    void *frontPadBuf = NULL;
    size_t frontHang, innerCount = 0;
    ssize_t r, ret = -1;

    if (fd == -1 || !buf || bsize <= 0)
        return -1;

    if (offset < 0)
        offset = lseek(fd, offset, SEEK_END);

    if (offset < 0)
        return -1;

    frontHang = offset % bsize;

    if (lseek(fd, offset - frontHang, SEEK_SET) < 0)
        return -1;

    if (frontHang && length) {
        if (posix_memalign(&frontPadBuf, alignment, bsize))
            return -1;

        innerCount = bsize - frontHang;
        if (innerCount > length)
            innerCount = length;

        r = readBuffer(fd, frontPadBuf, bsize);
        if (r < 0 || r < (ssize_t) (frontHang + innerCount))
            goto out;

        memcpy(buf, (char *) frontPadBuf + frontHang, innerCount);

        buf = (char *) buf + innerCount;
        length -= innerCount;
    }

    ret = readBlockwise(fd, bsize, alignment, buf, length);
    if (ret >= 0)
        ret += innerCount;
out:
    free(frontPadBuf);
    return ret;
}



