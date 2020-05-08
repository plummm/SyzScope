#!/bin/bash
# Xiaochen Zou 2020, University of California-Riverside
#
# Usage ./upload-exp.sh case_path syz_repro_url ssh_port image_path syz_commit

set -ex

if [ $# -ne 5 ]; then
  echo "Usage ./upload-exp.sh case_path syz_repro_url ssh_port image_path syz_commit"
  exit 1
fi

CASE_PATH=$1
TESTCASE=$2
PORT=$3
IMAGE_PATH=$4
SYZKALLER=$5

cd $CASE_PATH
if [ ! -d "$CASE_PATH/poc" ]; then
    mkdir $CASE_PATH/poc
fi

cd $CASE_PATH/poc
curl $TESTCASE > testcase
scp -F /dev/null -o UserKnownHostsFile=/dev/null \
    -o BatchMode=yes -o IdentitiesOnly=yes -o StrictHostKeyChecking=no \
    -i $IMAGE_PATH/stretch.id_rsa -P $PORT ./testcase root@localhost:/root

if [ ! -d "$CASE_PATH/gopath" ]; then
    mkdir $CASE_PATH/gopath
fi
export GOPATH=$CASE_PATH/gopath
if [ -d "$GOPATH/src/github.com/google/syzkaller" ]; then
    rm -rf $GOPATH/src/github.com/google/syzkaller
fi
go get -u -d github.com/google/syzkaller/prog
cd $GOPATH/src/github.com/google/syzkaller || exit 1
git checkout $SYZKALLER
make
scp -F /dev/null -o UserKnownHostsFile=/dev/null \
    -o BatchMode=yes -o IdentitiesOnly=yes -o StrictHostKeyChecking=no \
    -i $IMAGE_PATH/stretch.id_rsa -P $PORT bin/linux_amd64/syz-execprog bin/linux_amd64/syz-executor root@localhost:/root
exit 0