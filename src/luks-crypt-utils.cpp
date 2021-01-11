#include "luks-crypt-utils.h"
#include "luksactions.h"
#include "logger.h"
#include "random.h"
#include "config.h"
#include "utils.h"

#include "opensslcryptoprovider.h"
const char **action_argv;
int action_argc;
const char *null_action_argv[] = {NULL, NULL};


Logger *logger = new Logger();
Random *randomObj = new Random();

static struct action_type {
    const char *type;

    int (*handler)(void);

    int required_action_argc;
    const char *arg_desc;
    const char *desc;
} action_types[] = {
        {"addKey",        LuksActions::action_addKey,        1, ("<device> [<new key file>]"), ("add key to LUKS device")},
        {"removeKey",     LuksActions::action_removeKey,     1, ("<device> [<key file>]"),     ("removes supplied key or key file from LUKS device")},
        {"changeKey",     LuksActions::action_changeKey,     1, ("<device> [<key file>]"),     ("changes supplied key or key file of LUKS device")},
        {"killSlot",      LuksActions::action_killSlot,      2, ("<device> <key slot>"),       ("wipes key with number <key slot> from LUKS device")},
        {"UUID",          LuksActions::action_UUID,          1, ("<device>"),                  ("print UUID of LUKS device")},
        {"is_luks",       LuksActions::action_is_luks,       1, "<device>",                    "tests <device> for LUKS partition header"},
        {"decrypt",       LuksActions::action_decrypt,       1, "<device>",                    "decrypt LUKS <device>"},
        {"read_header",   LuksActions::action_readHeader,    1, "<device>",                    "dump LUKS partition information"},
        {"reencrypt",     LuksActions::action_reencrypt,     1, "<device>",                    "reencrypt <device>"},
        {"encrypt",       LuksActions::action_encrypt,       1, "<device>",                    "encrypt <device>"},
        {"headerBackup",  LuksActions::action_headerBackup,  1, ("<device>"),                  ("Backup LUKS device header and keyslots")},
        {"headerRestore", LuksActions::action_headerRestore, 1, ("<device>"),                  ("Restore LUKS device header and keyslots")},
        {"listHashAlgorithms", LuksActions::action_listHash, 0, (""),                          ("Print a list of all registered in openssl digest methods")},
        {"listCipherAlgorithms", LuksActions::action_listCipher, 0, (""),                          ("Print a list of all registered in openssl cipher algorithms")},
        {""}
};

__attribute__((noreturn)) void usage(poptContext popt_context,
                                     int exitcode, const char *error,
                                     const char *more) {
    poptPrintUsage(popt_context, stderr, 0);
    if (error)
        Logger::error("%s: %s", more, error);
    poptFreeContext(popt_context);
    exit(exitcode);
}

struct PbkdfType defaultLuks1 = {
        .type = (char *) CRYPT_KDF_PBKDF2,
        .hash = (char *) DEFAULT_LUKS1_HASH,
        .timeMs = DEFAULT_LUKS1_ITER_TIME
};

static void help(poptContext popt_context,
                 enum poptCallbackReason reason __attribute__((unused)),
                 struct poptOption *key,
                 const char *arg __attribute__((unused)),
                 void *data __attribute__((unused))) {
    if (key->shortName == '?') {
        struct action_type *action;
        const struct PbkdfType *pbkdf_luks1;

        Logger::info("%s\n", PACKAGE_STRING);

        poptPrintHelp(popt_context, stdout, 0);

        Logger::info("\n""<action> is one of:\n");

        for (action = action_types; action->type; action++)
            Logger::info("\t%s %s - %s\n", action->type, action->arg_desc, action->desc);


        pbkdf_luks1 = &defaultLuks1;
        Logger::info("\nDefault compiled-in key and passphrase parameters:\n"
                     "\tMaximum keyfile size: %dkB, "
                     "Maximum interactive passphrase length %d (characters)\n"
                     "Default PBKDF for LUKS1: %s, iteration time: %d (ms)\n",
                     DEFAULT_KEYFILE_SIZE_MAXKB, DEFAULT_PASSPHRASE_SIZE_MAX,
                     pbkdf_luks1->type, pbkdf_luks1->timeMs);

        Logger::info("\nDefault compiled-in device cipher parameters:\n"
                     "\tLUKS1: %s, Key: %d bits, LUKS header hashing: %s, RNG: %s\n",
                     DEFAULT_CIPHER(LUKS1), DEFAULT_LUKS1_KEYBITS, DEFAULT_LUKS1_HASH,
                     DEFAULT_RNG);
        exit(EXIT_SUCCESS);
    } else
        usage(popt_context, EXIT_SUCCESS, NULL, NULL);
}

static void help_args(struct action_type *action, poptContext popt_context) {
    char buf[128];

    snprintf(buf, sizeof(buf), "%s: requires %s as arguments", action->type, action->arg_desc);
    usage(popt_context, EXIT_FAILURE, buf, poptGetInvocationName(popt_context));
}


static int run_action(struct action_type *action) {
    int r;

    Logger::info("Running command %s.", action->type);
    OpenSSLCryptoProvider::initProvider();
    r = action->handler();
    OpenSSLCryptoProvider::destroyProvider();

    /* Some functions returns keyslot # */
    if (r > 0)
        r = 0;
    Utils::checkSignal(&r);

    Logger::status(r);
    return Utils::translateErrorCode(r);
}

void clearMemory() {
    if (logger)
        delete logger;
    if (randomObj)
        delete randomObj;
}

int main(int argc, char *argv[]) {
    static char *popt_tmp;
    static struct poptOption popt_help_options[] = {
            {NULL, '\0', POPT_ARG_CALLBACK, (void *) help, 0, NULL, NULL},
            {"help", '?', POPT_ARG_NONE, NULL, 0, ("Show this help message"), NULL},
            {"usage", '\0', POPT_ARG_NONE, NULL, 0, ("Display brief usage"), NULL},
            POPT_TABLEEND
    };
    static struct poptOption popt_options[] = {
            {NULL, '\0', POPT_ARG_INCLUDE_TABLE, popt_help_options, 0, ("Help options:"), NULL},
            {"version", '\0', POPT_ARG_NONE, &opt_version_mode, 0, ("Print package version"), NULL},
            {"verbose", 'v', POPT_ARG_NONE, &opt_verbose, 0, ("Shows more detailed error messages"), NULL},
            {"debug", '\0', POPT_ARG_NONE, &opt_debug, 0, ("Show debug messages"), NULL},
            {"cipher", 'c', POPT_ARG_STRING, &opt_cipher, 0, ("The cipher used to encrypt the disk (see luksCryptUtils listCipherAlgorithms)"),
             NULL},
            {"hash", 'h', POPT_ARG_STRING, &opt_hash, 0,
             ("The hash used to create the encryption key from the passphrase (see luksCryptUtils listHashAlgorithms)"), NULL},
            {"verify-passphrase", 'y', POPT_ARG_NONE, &opt_verify_passphrase, 0,
             ("Verifies the passphrase by asking for it twice"), NULL},
            {"key-file", 'd', POPT_ARG_STRING, &opt_key_file, 6, ("Read the key from a file"), NULL},
            {"new-key-file", 'd', POPT_ARG_STRING, &opt_new_key_file, 7, ("Read the new key from a file"), NULL},
            {"master-key-file", '\0', POPT_ARG_STRING, &opt_master_key_file, 0,
             ("Read the volume (master) key from file."), NULL},
            {"dump-master-key", '\0', POPT_ARG_NONE, &opt_dump_master_key, 0,
             ("Dump volume (master) key instead of keyslots info"), NULL},
            {"key-size", 's', POPT_ARG_INT, &opt_key_size, 0, ("The size of the encryption key"), ("BITS")},
            {"keyfile-size", 'l', POPT_ARG_LONG, &opt_keyfile_size, 0, ("Limits the read from keyfile"), ("bytes")},
            {"keyfile-offset", '\0', POPT_ARG_STRING, &popt_tmp, 4, ("Number of bytes to skip in keyfile"), ("bytes")},
            {"new-keyfile-size", '\0', POPT_ARG_LONG, &opt_new_keyfile_size, 0,
             ("Limits the read from newly added keyfile"), ("bytes")},
            {"new-keyfile-offset", '\0', POPT_ARG_STRING, &popt_tmp, 5,
             ("Number of bytes to skip in newly added keyfile"), ("bytes")},
            {"key-slot", 'S', POPT_ARG_INT, &opt_key_slot, 0, ("Slot number for new key (default is first free)"),
             NULL},
            {"timeout", 't', POPT_ARG_INT, &opt_timeout, 0, ("Timeout for interactive passphrase prompt (in seconds)"),
             ("secs")},
            {"align-payload", '\0', POPT_ARG_INT, &opt_align_payload, 0,
             ("Align payload at <n> sector boundaries - for luksFormat"), ("SECTORS")},
            {"header-backup-file", '\0', POPT_ARG_STRING, &opt_header_backup_file, 0, ("File with LUKS header and keyslots backup"), NULL},
            {"uuid", '\0', POPT_ARG_STRING, &opt_uuid, 0, ("UUID for device to use"), NULL},
            {"header", '\0', POPT_ARG_STRING, &opt_header_device, 0, ("Detached LUKS header"), NULL},
            {"new-header", '\0', POPT_ARG_STRING, &opt_new_header_device, 0,("Path for creating a new detached header"), NULL},
            {"device", '\0', POPT_ARG_STRING, &opt_device, 0, ("Target device or container"), NULL},
            {"output-file", '\0', POPT_ARG_STRING, &opt_output_file, 0, ("Output file"), NULL},
            {"test-passphrase", '\0', POPT_ARG_NONE, &opt_test_passphrase, 0,("Do not activate device, just check passphrase"), NULL},
            {"type", 'M', POPT_ARG_STRING, &opt_type, 0, ("Type of device metadata: luks, plain, loopaes, tcrypt"), NULL},
            {"iter-time", 'i', POPT_ARG_INT, &opt_iteration_time, 0, ("PBKDF iteration time for LUKS (in ms)"),("msecs")},
            {"sector-size", '\0', POPT_ARG_INT, &opt_sector_size, 0, ("Encryption sector size (default: 512 bytes)"),
             NULL},
            POPT_TABLEEND
    };
    poptContext popt_context;
    struct action_type *action;
    const char *aname;
    int r, total_keyfiles = 0;

    setlocale(LC_ALL, "");
    bindtextdomain(PACKAGE, LOCALEDIR);
    textdomain(PACKAGE);

    popt_context = poptGetContext(PACKAGE, argc, (const char **) argv, popt_options, 0);
    poptSetOtherOptionHelp(popt_context, "[OPTION...] <action> <action-specific>");

    while ((r = poptGetNextOpt(popt_context)) > 0) {
        unsigned long long ull_value;
        char *endp;

        if (r == 6) {
            const char *kf = poptGetOptArg(popt_context);
        if (opt_keyfiles_count < MAX_KEYFILES)
                opt_keyfiles[opt_keyfiles_count++] = kf;
            total_keyfiles++;
            continue;
        }

        errno = 0;
        ull_value = strtoull(popt_tmp, &endp, 0);
        if (*endp || !*popt_tmp || !isdigit(*popt_tmp) ||
            (errno == ERANGE && ull_value == ULLONG_MAX) ||
            (errno != 0 && ull_value == 0))
            r = POPT_ERROR_BADNUMBER;

        switch (r) {
            case 4:
                opt_keyfile_offset = ull_value;
                break;
            case 5:
                opt_new_keyfile_offset = ull_value;
                break;
        }

        if (r < 0)
            break;
    }

    if (r < -1)
        usage(popt_context, EXIT_FAILURE, poptStrerror(r), poptBadOption(popt_context, POPT_BADOPTION_NOALIAS));

    if (opt_version_mode) {
        Logger::info("%s %s\n", PACKAGE_NAME, PACKAGE_VERSION);
        poptFreeContext(popt_context);
        clearMemory();
        exit(EXIT_SUCCESS);
    }

    if (!(aname = poptGetArg(popt_context))) {
        clearMemory();
        usage(popt_context, EXIT_FAILURE, "Argument <action> missing.", poptGetInvocationName(popt_context));
    }
    action_argc = 0;
    action_argv = poptGetArgs(popt_context);
    /* Make return values of poptGetArgs more consistent in case of remaining argc = 0 */
    if (!action_argv)
        action_argv = null_action_argv;

    /* Count args, somewhat unnice, change? */
    while (action_argv[action_argc] != NULL)
        action_argc++;
    for (action = action_types; action->type; action++)
        if (strcmp(action->type, aname) == 0)
            break;

    if (!action->type)
        usage(popt_context, EXIT_FAILURE, "Unknown action.", poptGetInvocationName(popt_context));

    //if (action_argc < action->required_action_argc)
    //   help_args(action, popt_context);
    r = run_action(action);
    poptFreeContext(popt_context);


    clearMemory();
    return r;
}
