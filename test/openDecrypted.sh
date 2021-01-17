#!/bin/bash
echo "Open decrypted-with-mk";
mount -w decrypted-with-mk /home/owl/Desktop/gostDrive;
cat /home/owl/Desktop/gostDrive/testTxtFile.txt;
umount /home/owl/Desktop/gostDrive;
echo "Open decrypted-with-keyfile";
mount -w decrypted-with-keyfile /home/owl/Desktop/gostDrive;
cat /home/owl/Desktop/gostDrive/testTxtFile.txt;
umount /home/owl/Desktop/gostDrive;
echo "Open gost-essiv-decrypted";
mount -w gost-essiv-decrypted /home/owl/Desktop/gostDrive;
cat /home/owl/Desktop/gostDrive/testTxtFile.txt;
umount /home/owl/Desktop/gostDrive;

