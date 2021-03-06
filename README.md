# luks-crypt-utils
The grad project for MIEM HSE. (Research on dm-crypt + cryptsetup + luks)


## Usage examples
luks-crypt-utils works only with existing containters (no matter, if they are devices/files/folder/filesystems)

- encrypt:
```
luks-crypt-utils encrypt --header=<path>
```
- decrypt
```
luks-crypt-utils decrypt --header=<path>
```
- reencrypt
```
luks-crypt-utils reencrypt --device=<device to reencrypt> --output-file=<output device path>
```
- readHeader
```
luks-crypt-utils readHeader --header=<path> --dump-master-key
```
- isLUKS
```
luks-crypt-utils isLUKS --header=<path>
```
- addKey
```
luks-crypt-utils addKey --device=<path>
```
- removeKey
```
luks-crypt-utils removeKey --device=<path>
```
- changeKey
```
luks-crypt-utils changeKey --device=<path>
```
- killSlot
```
luks-crypt-utils killSlot --key-slot=<slot to kill> --device=<path>
```
- UUID
```
luks-crypt-utils UUID --device=<path>
```
- headerBackup
```
luks-crypt-utils headerBackup --device=<path> --header-backup-file=<path to header backup>
```
- headerRestore
```
luks-crypt-utils headerRestore --device=<path> --header-backup-file=<path to header backup>
```

