#!/bin/bash
# Xiaochen Zou 2020, University of California-Riverside
#
# Usage ./syz-compile.sh syzpath arch

if [ $# -ne 2 ]; then
  echo "Usage ./syz-compile.sh case_path arch"
  exit 1
fi

CASE_PATH=$1
SYZ_PATH=$CASE_PATH/gopath/src/github.com/google/syzkaller
ARCH=$2

export GOPATH=$CASE_PATH/gopath

cd $SYZ_PATH
rm CorrectTemplate
make generate || exit 1
make TARGETARCH=$ARCH TARGETVMARCH=amd64 || exit 1
exit 0