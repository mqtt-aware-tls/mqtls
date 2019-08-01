PWD=`pwd`
export LD_LIBRARY_PATH=$PWD/../tlsps-lib:$PWD/../openssl/lib
./mosquitto -c ../conf/mosquitto.conf
