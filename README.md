# pcapplusplus-examples

## Install pcapplusplus library on linux as below
apt-get install libpcap-dev buildessential
git clone -b v20.08 https://github.com/seladb/PcapPlusPlus.git
./configure-linux.sh —default
make all
make install

## Compiling
g++ -I /usr/local/include/pcapplusplus/ -L /usr/local/lib/ -static-libstdc++ -o test test.cc -lPcap++ -lPacket++ -lCommon++

