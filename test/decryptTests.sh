#!/bin/bash
echo "Test1. Device file does not exist";
luks-crypt-utils decrypt --device=non-existent-container;
echo "Test2. decrypt cryptsetup device with mk";
luks-crypt-utils decrypt --device=cryptsetupContainer --master-key-file=gost-mk --output-file=decrypted-with-mk;
echo "Test3. decrypt cryptsetup device with keyfile";
luks-crypt-utils decrypt --device=cryptsetupContainer --key-file=keyfile1  --output-file=decrypted-with-keyfile;
echo "Test4. Decrypt with kuznyechik-cbc with cipher essiv:streebog256, hash = streebog256 keyfile";
luks-crypt-utils decrypt --device=testGostEssiv --key-file=keyfile1 --output-file=gost-essiv-decrypted;
