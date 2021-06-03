#!/bin/bash
# Xiaochen Zou 2020, University of California-Riverside
#
# Usage ./patch_applying_check.sh linux_path linux_commit config_url patch_commit

set -ex
echo "running patch_applying_check.sh"


function jump_to_the_patch() {
    git stash
    git clean -fdx -e THIS_KERNEL_IS_BEING_USED > /dev/null
    #make clean CC=$COMPILER
    #git stash --all
    git checkout -f $PATCH
    git format-patch -1 $PATCH --stdout > fixed.patch
}

function copy_log_then_exit() {
  LOG=$1
  cp $LOG $CASE_PATH/$LOG-patch_applying_check
  exit 1
}

if [ $# -ne 6 ]; then
  echo "Usage ./patch_applying_check.sh linux_path linux_commit config_url patch_commit gcc_version max_compiling_kernel"
  exit 1
fi

LINUX=$1
COMMIT=$2
CONFIG=$3
PATCH=$4
COMPILER_VERSION=$5
MAX_COMPILING_KERNEL=$6
N_CORES=$((`nproc` / $MAX_COMPILING_KERNEL))
echo "Compiler: "$COMPILER_VERSION | grep gcc && \
COMPILER=`pwd`/tools/$COMPILER_VERSION/bin/gcc || COMPILER=`pwd`/tools/$COMPILER_VERSION/bin/clang

cd $LINUX
cd ..
CASE_PATH=`pwd`
cd linux

CURRENT_HEAD=`git rev-parse HEAD`
git stash
if [ "$CURRENT_HEAD" != "$COMMIT" ]; then
    git clean -fdx -e THIS_KERNEL_IS_BEING_USED > /dev/null
    #make clean CC=$COMPILER
    #git stash --all
    git checkout -f $COMMIT || (git pull https://github.com/torvalds/linux.git master > /dev/null 2>&1 && git checkout -f $COMMIT)
fi
git format-patch -1 $PATCH --stdout > fixed.patch
patch -p1 -N -i fixed.patch || jump_to_the_patch
patch -p1 -R < fixed.patch
curl $CONFIG > .config
sed -i "s/CONFIG_BUG_ON_DATA_CORRUPTION=y/# CONFIG_BUG_ON_DATA_CORRUPTION is not set/g" .config
make olddefconfig CC=$COMPILER
make -j$N_CORES CC=$COMPILER > make.log 2>&1 || copy_log_then_exit make.log
exit 0