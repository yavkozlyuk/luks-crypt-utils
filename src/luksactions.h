#pragma once
#ifndef LUKS_OPTIONS_H
#define LUKS_OPTIONS_H

#include "luksdevice.h"
#define MAX_KEYFILES		32

extern const char* opt_master_key_file;
extern const char* opt_header_backup_file;
extern const char* opt_key_file;
extern const char* opt_keyfile_stdin;
extern int opt_keyfiles_count;
extern const char* opt_keyfiles[MAX_KEYFILES];
extern const char* opt_uuid;
extern const char* opt_header_device;
extern const char* opt_device;
extern const char* opt_output_file;
extern const char* opt_type;
extern int opt_key_size;
extern long opt_keyfile_size;
extern long opt_new_keyfile_size;
extern uint64_t opt_keyfile_offset;
extern uint64_t opt_new_keyfile_offset;
extern int opt_key_slot;
extern int opt_token;
extern int opt_token_only;
extern uint64_t opt_size;
extern uint64_t opt_offset;
extern uint64_t opt_skip;
extern int opt_skip_valid;
extern int opt_readonly;
extern int opt_version_mode;
extern int opt_timeout;
extern int opt_tries;
extern int opt_align_payload;
extern int opt_random;
extern int opt_urandom;
extern int opt_dump_master_key;
extern int opt_shared;
extern int opt_allow_discards;
extern int opt_perf_same_cpu_crypt;
extern int opt_perf_submit_from_crypt_cpus;
extern int opt_test_passphrase;
extern int opt_deferred_remove;
//FIXME: check uint32 overflow for long type
extern const char* opt_pbkdf;
extern int opt_iteration_time;
extern int opt_disable_locks;
extern int opt_disable_keyring;
extern const char* opt_priority; /* normal */
extern const char* opt_key_description;
extern int opt_sector_size;
extern int opt_persistent;
extern const char* opt_label;
extern const char* opt_subsystem;
extern int opt_unbound;
extern int opt_verbose;
extern int opt_debug;
extern const char* opt_hash;
extern const char* opt_cipher;
extern int opt_verify_passphrase;

class LuksActions {
public:
	LuksActions();
	static int action_is_luks(void);
	static int action_decrypt(void);
	static int action_read_header(void);
	static int action_reencrypt(void);
	static int action_encrypt(void);
	static int action_luksAddKey(void);
	static int action_luksRemoveKey(void);
	static int action_luksChangeKey(void);
	static int action_luksKillSlot(void);
	static int action_luksUUID(void);
};

#endif // LUKS_OPTIONS_H
