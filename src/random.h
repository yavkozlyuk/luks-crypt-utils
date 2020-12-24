#pragma once
#ifndef RANDOM_H
#define RANDOM_H

#include <stddef.h>

class Random {
public:
    Random();

    virtual ~Random();

    int getRandom(unsigned char *buf, size_t len);

private:
    int randomfd = -1;
};

#endif // RANDOM_H
