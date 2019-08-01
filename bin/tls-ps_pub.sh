PWD=`pwd`
export LD_LIBRARY_PATH=$PWD/../tlsps-lib:$PWD/../openssl/lib
./mosquitto_tlsps_pub -t hello -m test --cafile ../certs/demoCA/cacert.pem -h www.rsa.com --key ../certs/publisher_priv.pem --cert ../certs/publisher_pub.pem
