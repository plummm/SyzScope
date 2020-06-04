#!/bin/bash
# Xiaochen Zou 2020, University of California-Riverside
#
# Usage ./patch_applying_check.sh linux_path linux_commit config_url patch_commit

set -ex
echo "running patch_applying_check.sh"


function jump_to_the_patch() {
    git stash
    #make clean CC=$GCC
    #git stash --all
    git checkout $PATCH
    git format-patch -1 $PATCH --stdout > fixed.patch
}

function copy_log_then_exit() {
  LOG=$1
  cp $LOG $CASE_PATH
  exit 1
}

if [ $# -ne 4 ]; then
  echo "Usage ./patch_applying_check.sh linux_path linux_commit config_url patch_commit"
  exit 1
fi

LINUX=$1
COMMIT=$2
CONFIG=$3
PATCH=$4
GCC=`pwd`/tools/gcc/bin/gcc

cd $LINUX
cd ..
CASE_PATH=`pwd`
cd linux

CURRENT_HEAD=`git rev-parse HEAD`
git stash
if [ "$CURRENT_HEAD" != "$COMMIT" ]; then
    #make clean CC=$GCC
    #git stash --all
    git pull https://github.com/torvalds/linux.git master > /dev/null 2>&1
    git checkout $COMMIT
fi
git format-patch -1 $PATCH --stdout > fixed.patch
patch -p1 -N -i fixed.patch || jump_to_the_patch
patch -p1 -R < fixed.patch
curl $CONFIG > .config
make olddefconfig
make -j16 > make.log 2>&1 || copy_log_then_exit make.log
exit 0