#!/bin/bash
# Xiaochen Zou 2020, University of California-Riverside
#
# Usage ./deplay-bc.sh linux_clone_path index case_path commit config

set -ex

echo "running deploy-bc.sh"

function copy_log_then_exit() {
  LOG=$1
  cp $LOG $CASE_PATH/wllvm-$LOG
}

function config_disable() {
  key=$1
  sed -i "s/$key=n/# $key is not set/g" .config
  sed -i "s/$key=m/# $key is not set/g" .config
  sed -i "s/$key=y/# $key is not set/g" .config
}

function config_enable() {
  key=$1
  sed -i "s/$key=n/# $key is not set/g" .config
  sed -i "s/$key=m/# $key is not set/g" .config
  sed -i "s/# $key is not set/$key=y/g" .config
}

if [ $# -ne 7 ]; then
  echo "Usage ./deploy-bc.sh linux_clone_path index case_path commit config bc_path compile"
  exit 1
fi

INDEX=$2
CASE_PATH=$3
COMMIT=$4
CONFIG=$5
BC_PATH=$6
COMPILE=$7
PROJECT_PATH="$(pwd)"

cd $CASE_PATH

OLD_INDEX=`ls -l linux | cut -d'-' -f 3`
if [ "$OLD_INDEX" != "$INDEX" ]; then
  if [ -d "./linux" ]; then
      rm -rf "./linux"
  fi
  ln -s $PROJECT_PATH/tools/$1-$INDEX ./linux
  if [ -f "$CASE_PATH/.stamp/BUILD_KERNEL" ]; then
      rm $CASE_PATH/.stamp/BUILD_KERNEL
  fi
fi

cd linux
if [ -f "THIS_KERNEL_IS_BEING_USED" ]; then
    echo "This kernel is using by other thread"
    exit 1
fi

if [ "$COMPILE" != "1" ]; then
git stash

find -type f -name '*.bc' ! -name "timeconst.bc" -delete
git clean -fdx -e THIS_KERNEL_IS_BEING_USED > /dev/null || echo "cleanning interrupt"
git checkout -f $COMMIT || (git pull https://github.com/torvalds/linux.git master > /dev/null 2>&1 && git checkout -f $COMMIT)

#Add a rejection detector in future
curl $CONFIG > .config

else

#export LLVM_COMPILER=clang
#export LLVM_COMPILER_PATH=$PROJECT_PATH/tools/llvm/build/bin/
CLANG=$PROJECT_PATH/tools/llvm/build/bin/clang
#pip list | grep wllvm || pip install wllvm
CONFIGKEYSDISABLE="
CONFIG_KASAN
CONFIG_KCOV
CONFIG_BUG_ON_DATA_CORRUPTION
"
for key in $CONFIGKEYSDISABLE;
do
    config_disable $key
done

make olddefconfig CC=$CLANG
find -type f -name '*.o' -delete
find -type f -name '*.bc' ! -name "timeconst.bc" -delete
make -n CC=$CLANG > wllvm_log || echo "It's OK"
exit 1