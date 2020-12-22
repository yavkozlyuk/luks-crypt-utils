#pragma once
#ifndef LOGGER_H
#define LOGGER_H

#include <iostream>
#include <cstdarg>
#include "luksconstants.h"

enum LogLevel { INFO, DEBUG, ERROR, WARN };

class Logger
{
public:
    Logger();
    static void log(LogLevel level, const char* msg, ...);
    static void error(const char* msg, ...);
    static void debug(const char *msgArgs, ...);
    static void info(const char *msgArgs, ...);
    static void warn(const char *msgArgs, ...);
    static void passphraseMsg(int r);
    static void keyslotMsg(int keyslot, cryptObjectOp op);
    static void status(int errcode);
};
#endif // LOGGER_H
