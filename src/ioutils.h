#pragma once
#ifndef IOUTILS_H
#define IOUTILS_H

#include <sys/types.h>

class IOUtils {
public:
    IOUtils();

    static ssize_t readBuffer(int fd, void *buf, size_t length);

    static ssize_t readBufferIntr(int fd, void *buf, size_t length, volatile int *quit);

    static ssize_t writeBuffer(int fd, const void *buf, size_t length);

    static ssize_t writeBufferIntr(int fd, const void *buf, size_t length, volatile int *quit);

    static ssize_t writeBlockwise(int fd, size_t bsize, size_t alignment, void *orig_buf, size_t length);

    static ssize_t readBlockwise(int fd, size_t bsize, size_t alignment, void *orig_buf, size_t length);

    static ssize_t writeLseekBlockwise(int fd, size_t bsize, size_t alignment, void *buf, size_t length, off_t offset);

    static ssize_t readLseekBlockwise(int fd, size_t bsize, size_t alignment, void *buf, size_t length, off_t offset);
};

#endif // IOUTILS_H
