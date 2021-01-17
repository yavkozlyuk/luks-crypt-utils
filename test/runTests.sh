#!/bin/bash
chmod +x ./*.sh;
sudo ./createCryptsetupContainer.sh;
./encryptDecryptTests.sh
sudo ./openDecrypted.sh;
