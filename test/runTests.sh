#!/bin/bash
chmod +x ./*.sh;
sudo ./createCryptsetupContainer.sh;
./encryptTests.sh
./decryptTests.sh
sudo ./openDecrypted.sh;
