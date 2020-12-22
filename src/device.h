#pragma once
#ifndef DEVICE_H
#define DEVICE_H


#include <sys/types.h>
class Device
{
public:
    Device();
private:
    char *path;

    char *file_path;
    int loop_fd;

    struct crypt_lock_handle *lh;

    unsigned int o_direct:1;
    unsigned int init_done:1;

    /* cached values */
    size_t alignment;
    size_t block_size;
};

#endif // DEVICE_H
