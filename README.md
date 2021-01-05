# luks-crypt-utils
The grad project for MIEM HSE. (Research on dm-crypt + cryptsetup + luks)

# Requirements:

openssl v1.1.1
libssl-dev
uuid-dev libdevmapper-dev libopt-dev libgcrypt20-dev
blkid-dev

openssl GOST engine - https://github.com/gost-engine/engine/tree/openssl_1_1_1


# Usage
luks-crypt-utils works only with existing containters (no matter, if they are devices/files/folder/filesystems)

- encrypt:
./luks-crypt-utils encrypt --header=<path>
- decrypt
./luks-crypt-utils decrypt --header=<path>
- reencrypt
./luks-crypt-utils reencrypt --device=<device to reencrypt> --output-file=<output device path>
- read_header
./luks-crypt-utils read_header --header=<path> --dump-master-key
- is_luks
./luks-crypt-utils is_luks --header=<path>
- addKey
./luks-crypt-utils addKey --device=<path>
- removeKey
- changeKey
- killSlot
./luks-crypt-utils killSlot --key-slot=<slot to kill> --device=<path>
- UUID
- headerBackup
/luks-crypt-utils headerBackup --device=<path> --header-backup-file=<path to header backup>
- headerRestore
/luks-crypt-utils headerRestore --device=<path> --header-backup-file=<path to header backup>

