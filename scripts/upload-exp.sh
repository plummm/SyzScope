#!/bin/bash
# Xiaochen Zou 2020, University of California-Riverside
#
# Usage ./upload-exp.sh case_path poc_url ssh_port image_path

set -ex

if [ $# -ne 4 ]; then
  echo "Usage ./upload-exp.sh case_path poc_url ssh_port image_path"
  exit 1
fi

CASE_PATH=$1
POC=$2
PORT=$3
IMAGE_PATH=$4

cd $CASE_PATH
if [ ! -d "$CASE_PATH/poc" ]; then
    mkdir $CASE_PATH/poc
fi

cd $CASE_PATH/poc
curl $POC > poc.c
gcc -pthread -o poc poc.c || exit 1

scp -F /dev/null -o UserKnownHostsFile=/dev/null \
    -o BatchMode=yes -o IdentitiesOnly=yes -o StrictHostKeyChecking=no \
    -i $IMAGE_PATH/stretch.id_rsa -P $PORT ./poc root@localhost:/root
exit 0