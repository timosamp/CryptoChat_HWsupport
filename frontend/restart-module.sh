#!/bin/bash
#set -e
make clean
make
rmmod virtio_crypto.ko
insmod ./virtio_crypto.ko
./crypto_dev_nodes.sh
