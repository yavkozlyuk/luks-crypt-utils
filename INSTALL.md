#####Required packages:

* qt5-qmake (for luks-crypt-utils installation)
* cmake (for gost engine installation)
* libssl-dev
* libpopt-dev
* uuid-dev
* openssl v1.1.1f
* g++
* openssl GOST engine (https://github.com/gost-engine/engine/tree/openssl_1_1_1)

#####OpenSSL GOST engine installation.
To build and install openssl GOST engine follow instructions in https://github.com/gost-engine/engine/blob/openssl_1_1_1/INSTALL.md

_How to solve possible errors during build_:
* “Unable to discover the OpenSSL engines directory” - provide -DOPENSSL_ENGINES_DIR option with value from `openssl version -a | grep “ENGINESDIR”`
* “Unable to discover the OpenSSL engines directory” - provide -DOPENSSL_ROOT_DIR option with value from  `openssl version -a | grep “OPENSSLDIR”`

__Note:__ Do not forget to change  DynamicPath parameter in openssl.cnf to `ENGINESDIR/gost.so`

#####luks-crypt-utils installation

1. run sudo apt-get --yes  install g++ qt5-qmake cmake libpopt-dev libssl-dev uuid-dev
2. check openssl version
3. install openssl GOST engine
4. git repo or download zip to get luks-crypt-utils sources
5. enter luks-crypt-utils dir
6. run sudo make install

