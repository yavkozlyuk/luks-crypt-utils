#!/bin/bash

luks-crypt-utils decrypt --device=cryptsetupContainer --master-key-file=gost-mk --output-file=luks-crypt-utilsContainer;

echo "Test1. Device file does not  exist";
luks-crypt-utils encrypt --device=non-existent-container;
echo "Test2. Encrypt with aes-128-xts with essiv:sha256 and keyfile";
luks-crypt-utils encrypt --device=luks-crypt-utilsContainer --cipher=aes-xts-essiv:sha256 --key-size=256 --key-file=keyfile1 --output-file=testAesEssiv;
luks-crypt-utils readHeader --device=testAesEssiv;
echo "Test3. Encrypt with kuznyechik-cbc with cipher essiv:streebog256, hash = streebog256 keyfile";
luks-crypt-utils encrypt --device=luks-crypt-utilsContainer --cipher=kuznyechik-cbc-essiv:streebog256 --key-file=keyfile1 --hash=streebog256 --output-file=testGostEssiv;
luks-crypt-utils readHeader --device=testGostEssiv;

#!/bin/bash
echo "Test1. Device file does not exist";
luks-crypt-utils decrypt --device=non-existent-container;
echo "Test2. decrypt cryptsetup device with mk";
luks-crypt-utils decrypt --device=cryptsetupContainer --master-key-file=gost-mk --output-file=decrypted-with-mk;
echo "Test3. decrypt cryptsetup device with keyfile";
luks-crypt-utils decrypt --device=cryptsetupContainer --key-file=keyfile1  --output-file=decrypted-with-keyfile;
echo "Test4. Decrypt with kuznyechik-cbc with cipher essiv:streebog256, hash = streebog256 keyfile";
luks-crypt-utils decrypt --device=testGostEssiv --key-file=keyfile1 --output-file=gost-essiv-decrypted;
