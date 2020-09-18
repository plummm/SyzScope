#!/bin/bash
# Xiaochen Zou 2020, University of California-Riverside
#
# Usage ./patch_applying_check.sh linux_path linux_commit config_url patch_commit

set -ex
echo "running patch_applying_check.sh"


function jump_to_the_patch() {
    git stash
    git clean -d -f -e THIS_KERNEL_HAS_BEEN_USED
    #make clean CC=$GCC
    #git stash --all
    git checkout -f $PATCH
    git format-patch -1 $PATCH --stdout > fixed.patch
}

function copy_log_then_exit() {
  LOG=$1
  cp $LOG $CASE_PATH/$LOG-patch_applying_check
  exit 1
}

if [ $# -ne 5 ]; then
  echo "Usage ./patch_applying_check.sh linux_path linux_commit config_url patch_commit gcc_version"
  exit 1
fi

LINUX=$1
COMMIT=$2
CONFIG=$3
PATCH=$4
GCCVERSION=$5
GCC=`pwd`/tools/$GCCVERSION/bin/gcc

cd $LINUX
cd ..
CASE_PATH=`pwd`
cd linux

CURRENT_HEAD=`git rev-parse HEAD`
git stash
if [ "$CURRENT_HEAD" != "$COMMIT" ]; then
    git clean -d -f -e THIS_KERNEL_HAS_BEEN_USED
    #make clean CC=$GCC
    #git stash --all
    git checkout -f $COMMIT || (git pull https://github.com/torvalds/linux.git master > /dev/null 2>&1 && git checkout -f $COMMIT)
fi
git format-patch -1 $PATCH --stdout > fixed.patch
patch -p1 -N -i fixed.patch || jump_to_the_patch
patch -p1 -R < fixed.patch
curl $CONFIG > .config
sed -i "s/CONFIG_BUG_ON_DATA_CORRUPTION=y/# CONFIG_BUG_ON_DATA_CORRUPTION is not set/g" .config
make olddefconfig CC=$GCC
make -j16 CC=$GCC > make.log 2>&1 || copy_log_then_exit make.log
exit 0