#pragma once
#ifndef CONFIG_H
#define CONFIG_H

#define OPENSSL_LOAD_CONF
#define PACKAGE "luks-crypt-utils"
/* Define to the full name of this package. */
#define PACKAGE_NAME "luks-crypt-utils"

#ifndef LOCALEDIR
#define LOCALEDIR "/usr/share/locale"
#endif
/* Define to the full name and version of this package. */
#define PACKAGE_STRING "luks-crypt-utils 0.0.1"

#define PACKAGE_VERSION "0.0.1"

/* default RNG type for key generator */
#define DEFAULT_RNG "/dev/urandom"


/* Argon2 PBKDF iteration time for LUKS2 (in ms) */
#define DEFAULT_LUKS2_ITER_TIME 2000

/* default luks2 locking directory permissions */
#define DEFAULT_LUKS2_LOCK_DIR_PERMS 0700

/* path to directory for LUKSv2 locks */
#define DEFAULT_LUKS2_LOCK_PATH "/run/cryptsetup"

/* Argon2 PBKDF memory cost for LUKS2 (in kB) */
#define DEFAULT_LUKS2_MEMORY_KB 1048576

/* Argon2 PBKDF max parallel cost for LUKS2 (if CPUs available) */
#define DEFAULT_LUKS2_PARALLEL_THREADS 4

/* Default PBKDF algorithm (pbkdf2 or argon2i/argon2id) for LUKS2 */
#define DEFAULT_LUKS2_PBKDF "argon2i"


#endif // CONFIG_H
