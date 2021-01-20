#!/bin/bash
# Xiaochen Zou 2020, University of California-Riverside
#
# Usage ./deplay-bc.sh linux_clone_path index case_path commit config

set -ex

echo "running deploy-bc.sh"

function copy_log_then_exit() {
  LOG=$1
  cp $LOG $CASE_PATH/clang-$LOG
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

if [ "$COMPILE" != "1" ]; then

  if [ -f "$CASE_PATH/config" ]; then
    rm .config
    mv $CASE_PATH/config .config
    if [ ! -f "$CASE_PATH/compiler/compiler" ]; then
      echo "No compiler found in $CASE_PATH"
      exit 1
    fi
    COMPILER=$CASE_PATH/compiler/compiler
    make -j16 CC=$COMPILER > make.log 2>&1 || copy_log_then_exit make.log
    exit 0
  fi

else

CONFIGKEYSDISABLE="
CONFIG_KASAN
CONFIG_KCOV
CONFIG_BUG_ON_DATA_CORRUPTION
"
for key in $CONFIGKEYSDISABLE;
do
    config_disable $key
done

CLANG=$PROJECT_PATH/tools/llvm/build/bin/clang
make olddefconfig CC=$CLANG
#export LLVM_COMPILER=clang
#export LLVM_COMPILER_PATH=$PROJECT_PATH/tools/llvm/build/bin/
#pip list | grep wllvm || pip install wllvm
find -type f -name '*.bc' ! -name "timeconst.bc" -delete
make -n CC=$CLANG > clang_log || echo "It's OK"
exit 1
fi