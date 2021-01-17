TEMPLATE = app
CONFIG += console c++11
CONFIG -= app_bundle
CONFIG -= qt

LIBS += -lcrypto -lssl -lm -lpopt -luuid

SOURCES += \
    src/afutils.cpp \
    src/cipher.cpp \
    src/hashfunction.cpp \
    src/ioutils.cpp \
    src/key.cpp \
    src/logger.cpp \
    src/luks-crypt-utils.cpp \
    src/luksactions.cpp \
    src/luksdevice.cpp \
    src/lukspartitionheader.cpp \
    src/luksstorage.cpp \
    src/opensslcryptoprovider.cpp \
    src/pbkdf.cpp \
    src/random.cpp \
    src/storagekey.cpp \
    src/utils.cpp

HEADERS += \
    src/afutils.h \
    src/bitops.h \
    src/cipher.h \
    src/config.h \
    src/hashfunction.h \
    src/ioutils.h \
    src/key.h \
    src/logger.h \
    src/luks-crypt-utils.h \
    src/luksactions.h \
    src/luksconstants.h \
    src/luksdevice.h \
    src/lukspartitionheader.h \
    src/luksstorage.h \
    src/opensslcryptoprovider.h \
    src/pbkdf.h \
    src/random.h \
    src/storagekey.h \
    src/utils.h


DISTFILES += \
    .gitignore \
    Makefile \
    README.md \
    test/createCryptsetupContainer.sh \
    test/decryptTests.sh \
    test/encryptDecryptTests.sh \
    test/openDecrypted.sh \
    test/runTests.sh

target.path = /usr/local/bin/
INSTALLS += target
