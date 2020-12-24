#include "logger.h"
#include "utils.h"

#define LOG_MAX_LEN 4096

extern int opt_verbose;
extern int opt_debug;


Logger::Logger() {
}

void log_internal(LogLevel level, const char *format, va_list argp) {
    char msg[LOG_MAX_LEN + 2];

    if (vsnprintf(&msg[0], LOG_MAX_LEN, format, argp) > 0) {
        switch (level) {
            case LogLevel::INFO:
                std::cout << msg << std::endl;
                break;
            case LogLevel::WARN:
                if (opt_verbose)
                    std::cout << msg << std::endl;
                break;
            case LogLevel::ERROR:
                std::cerr << msg << std::endl;
                break;
            case LogLevel::DEBUG:
                if (opt_debug)
                    std::cout << msg << std::endl;
                break;
            default:
                std::cerr << "Internal error on logging class for msg: " << msg << std::endl;
                break;
        }
    }
}

void Logger::log(LogLevel level, const char *msg, ...) {
    va_list argp;
    va_start(argp, msg);
    log_internal(level, msg, argp);
    va_end(argp);
}

void Logger::error(const char *msg, ...) {
    va_list argp;
    va_start(argp, msg);
    log_internal(LogLevel::ERROR, msg, argp);
    va_end(argp);
}

void Logger::debug(const char *msg, ...) {
    va_list argp;
    va_start(argp, msg);
    log_internal(LogLevel::DEBUG, msg, argp);
    va_end(argp);
}

void Logger::warn(const char *msg, ...) {
    va_list argp;
    va_start(argp, msg);
    log_internal(LogLevel::WARN, msg, argp);
    va_end(argp);
}

void Logger::info(const char *msg, ...) {
    va_list argp;
    va_start(argp, msg);
    log_internal(LogLevel::INFO, msg, argp);
    va_end(argp);
}

void Logger::passphraseMsg(int r) {
    if (r == -EPERM)
        Logger::error("No key available with this passphrase.");
}

void Logger::keyslotMsg(int keyslot, cryptObjectOp op) {
    if (keyslot < 0)
        return;

    if (op == CREATED)
        Logger::warn("Key slot %i created.", keyslot);
    else if (op == UNLOCKED)
        Logger::warn("Key slot %i unlocked.", keyslot);
    else if (op == REMOVED)
        Logger::warn("Key slot %i removed.", keyslot);
}

void Logger::status(int errcode) {
    char const *crypt_error;

    if (!opt_verbose)
        return;

    if (!errcode) {
        info("Command successful.\n");
        return;
    }

    if (errcode < 0)
        errcode = Utils::translateErrorCode(errcode);
    switch (errcode) {
        case 1:
            crypt_error = "wrong or missing parameters";
            break;
        case 2:
            crypt_error = "no permission or bad passphrase";
            break;
        case 3:
            crypt_error = "out of memory";
            break;
        case 4:
            crypt_error = "wrong device or file specified";
            break;
        case 5:
            crypt_error = "device already exists or device is busy";
            break;
        default:
            crypt_error = "unknown error";
    }

    info("Command failed with code %i (%s).\n", -errcode, crypt_error);
}

