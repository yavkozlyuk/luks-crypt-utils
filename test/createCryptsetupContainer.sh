#!/bin/bash
echo "Creating cryptsetupContainer";
rm -f cryptsetupContainer;
dd if=/dev/zero of=./cryptsetupContainer bs=1 count=0 seek=10M;
echo "Creating keyfile1";
echo "gostkey1" > keyfile1;
echo "keyfile1 contents:";
cat keyfile1;
cryptsetup luksFormat cryptsetupContainer --cipher=kuznyechik-cbc-plain64  --hash=whirlpool --type=luks1 --key-file=keyfile1;
cryptsetup luksOpen cryptsetupContainer cryptsetupDevice --key-file=keyfile1;
mkfs.ext4 /dev/mapper/cryptsetupDevice;
mount -w /dev/mapper/cryptsetupDevice /home/owl/Desktop/gostDrive;
echo "This file has been created for test purposes" > /home/owl/Desktop/gostDrive/testTxtFile.txt;
umount /home/owl/Desktop/gostDrive;
cryptsetup luksClose cryptsetupDevice;


echo "Dumping cryptsetupContainer metadata with cryptsetup";
cryptsetup luksDump cryptsetupContainer;
echo "Dumping cryptsetupContainer master-key to \"gost-mk\" file";
cryptsetup luksDump cryptsetupContainer --dump-master-key --key-file=keyfile1 --master-key-file=gost-mk;
