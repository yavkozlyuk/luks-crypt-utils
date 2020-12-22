#include "random.h"
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>
#include <stdio.h>
#include <unistd.h>
Random::Random() {
    if(randomfd == -1)
        randomfd = open("/dev/urandom", O_RDONLY);
}

Random::~Random() {
    if(randomfd != -1) {
        close(randomfd);
        randomfd = -1;
    }
}

int Random::getRandom(unsigned char *buf, size_t len) {
    if(randomfd == -1) {
        perror("getRandom:");
        return -EINVAL;
    }
    while(len) {
        int r;
        r = read(randomfd,buf,len);
        if (-1 == r && errno != -EINTR) {
            perror("read: "); return -EINVAL;
        }
        len-= r; buf += r;
    }
    return 0;
}
