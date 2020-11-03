# pcapplusplus-examples

## Install pcapplusplus library on linux as below
```shell
apt-get install libpcap-dev build-essential
git clone -b v20.08 https://github.com/seladb/PcapPlusPlus.git
./configure-linux.sh —default
make all
make install
```
## Compiling
```shell
g++ -I /usr/local/include/pcapplusplus/ -L /usr/local/lib/ -static-libstdc++ -o example example.cc -lPcap++ -lPacket++ -lCommon++
```
