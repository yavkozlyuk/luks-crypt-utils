#pragma once
#include "config.h"

#ifndef LUKSCONSTANTS_H
#define LUKSCONSTANTS_H
#define LUKS_MAGIC {'L','U','K','S', (char)0xba, (char)0xbe};
#define LUKS_MAGIC_L 6
#define LUKS_CIPHERNAME_L 32
#define LUKS_CIPHERMODE_L 32
#define LUKS_HASHSPEC_L 32
#define UUID_STRING_L 40
#define LUKS_DIGEST_SIZE 20
#define LUKS_SALT_SIZE 32
#define LUKS_NUMKEYS 8
#define LUKS_KEY_DISABLED 0x0000DEAD
#define LUKS_KEY_ENABLED 0x00AC71F3
#define LUKS_DIGEST_SIZE 20
#define SECTOR_SIZE 512
#define HEADER_SIZE 592
#define SECTOR_SHIFT 9
#define LUKS_STRIPES 4000
/* Offset to keyslot area [in bytes] */
#define LUKS_ALIGN_KEYSLOTS 4096

#define MAX_CIPHER_LEN		32
#define MAX_CIPHER_LEN_STR	"31"



/* default LUKS format version */
#define DEFAULT_LUKS_FORMAT CRYPT_LUKS1


/* cipher for LUKS1 */
#define DEFAULT_LUKS1_CIPHER "aes"
/* hash function for LUKS1 header */
#define DEFAULT_LUKS1_HASH "sha256"
/* PBKDF2 iteration time for LUKS1 (in ms) */
#define DEFAULT_LUKS1_ITER_TIME 2000
/* key length in bits for LUKS1 */
#define DEFAULT_LUKS1_KEYBITS 256
/* cipher mode for LUKS1 */
#define DEFAULT_LUKS1_MODE "xts-plain64"
/** LUKS version 1 header on-disk */
#define CRYPT_LUKS1 "LUKS1"
/** LUKS version 2 header on-disk */
#define CRYPT_LUKS2 "LUKS2"
/** LUKS any version */
#define CRYPT_LUKS CRYPT_LUKS1

/** device is read only */
#define CRYPT_ACTIVATE_READONLY (1 << 0)
/** only reported for device without uuid */
#define CRYPT_ACTIVATE_NO_UUID  (1 << 1)
/** activate even if cannot grant exclusive access (DANGEROUS) */
#define CRYPT_ACTIVATE_SHARED   (1 << 2)
/** enable discards aka TRIM */
#define CRYPT_ACTIVATE_ALLOW_DISCARDS (1 << 3)
/** skip global udev rules in activation ("private device"), input only */
#define CRYPT_ACTIVATE_PRIVATE (1 << 4)
/** corruption detected (verity), output only */
#define CRYPT_ACTIVATE_CORRUPTED (1 << 5)
/** use same_cpu_crypt option for dm-crypt */
#define CRYPT_ACTIVATE_SAME_CPU_CRYPT (1 << 6)
/** use submit_from_crypt_cpus for dm-crypt */
#define CRYPT_ACTIVATE_SUBMIT_FROM_CRYPT_CPUS (1 << 7)
/** dm-verity: ignore_corruption flag - ignore corruption, log it only */
#define CRYPT_ACTIVATE_IGNORE_CORRUPTION (1 << 8)
/** dm-verity: restart_on_corruption flag - restart kernel on corruption */
#define CRYPT_ACTIVATE_RESTART_ON_CORRUPTION (1 << 9)
/** dm-verity: ignore_zero_blocks - do not verify zero blocks */
#define CRYPT_ACTIVATE_IGNORE_ZERO_BLOCKS (1 << 10)
/** key loaded in kernel keyring instead directly in dm-crypt */
#define CRYPT_ACTIVATE_KEYRING_KEY (1 << 11)
/** dm-integrity: direct writes, do not use journal */
#define CRYPT_ACTIVATE_NO_JOURNAL (1 << 12)
/** dm-integrity: recovery mode - no journal, no integrity checks */
#define CRYPT_ACTIVATE_RECOVERY (1 << 13)
/** ignore persistently stored flags */
#define CRYPT_ACTIVATE_IGNORE_PERSISTENT (1 << 14)
/** dm-verity: check_at_most_once - check data blocks only the first time */
#define CRYPT_ACTIVATE_CHECK_AT_MOST_ONCE (1 << 15)
/** allow activation check including unbound keyslots (keyslots without segments) */
#define CRYPT_ACTIVATE_ALLOW_UNBOUND_KEY (1 << 16)

#define CRYPT_ANY_TOKEN -1
/** iterate through all keyslots and find first one that fits */
#define CRYPT_ANY_SLOT -1




/** PBKDF2 according to RFC2898, LUKS1 legacy */
#define CRYPT_KDF_PBKDF2   "pbkdf2"
/** Argon2i according to RFC */
#define CRYPT_KDF_ARGON2I  "argon2i"
/** Argon2id according to RFC */
#define CRYPT_KDF_ARGON2ID "argon2id"

// Minimal number of iterations
#define LUKS_MKD_ITERATIONS_MIN  1000
#define LUKS_SLOT_ITERATIONS_MIN 1000

#define LUKS_MKD_ITERATIONS_MS 125

#define MISALIGNED(a, b)	((a) & ((b) - 1))
#define MISALIGNED_512(a)	MISALIGNED((a), 1 << SECTOR_SHIFT)
#define DEFAULT_MEM_ALIGNMENT	4096
#define DEFAULT_DISK_ALIGNMENT	1048576 /* 1MiB */
typedef enum { CREATED, UNLOCKED, REMOVED  } cryptObjectOp;


/** Read key only to the first end of line (\\n). */
#define CRYPT_KEYFILE_STOP_EOL   (1 << 0)

typedef enum {
    SLOT_INVALID,    /**< invalid keyslot */
    SLOT_INACTIVE,   /**< keyslot is inactive (free) */
    SLOT_ACTIVE,     /**< keyslot is active (used) */
    SLOT_ACTIVE_LAST,/**< keylost is active (used)
                 *  and last used at the same time */
    SLOT_UNBOUND     /**< keyslot is active and not bound
                 *  to any crypt segment (LUKS2 only) */
} KeySlotInfo;

#define DEFAULT_CIPHER(type)	(DEFAULT_##type##_CIPHER "-" DEFAULT_##type##_MODE)

#endif // LUKSCONSTANTS_H
