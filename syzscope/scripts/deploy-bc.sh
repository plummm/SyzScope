#!/bin/bash
# Xiaochen Zou 2020, University of California-Riverside
#
# Usage ./deplay-bc.sh linux_clone_path index case_path commit config

set -ex

echo "running deploy-bc.sh"

function wait_for_other_compiling() {
  # sometime a process may strave to a long time, seems ok if every case has the same weight
  n=`ps aux | grep "make -j" | wc -l`
  echo "Wait for other compiling"
  set +x
  while [ $n -ge $(($MAX_COMPILING_KERNEL+1)) ]
  do
    sleep 10
    n=`ps aux | grep "make -j" | wc -l`
  done
  set -x
}

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

if [ $# -ne 8 ]; then
  echo "Usage ./deploy-bc.sh linux_clone_path index case_path commit config bc_path compile max_compiling_kernel"
  exit 1
fi

INDEX=$2
CASE_PATH=$3
COMMIT=$4
CONFIG=$5
BC_PATH=$6
COMPILE=$7
MAX_COMPILING_KERNEL=$8
N_CORES=$((`nproc` / $MAX_COMPILING_KERNEL))
PROJECT_PATH="$(pwd)"
export PATH=$PATH:/home/xzou017/.local/bin

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
    git stash
    rm .config
    cp $CASE_PATH/config .config
    if [ ! -f "$CASE_PATH/compiler/compiler" ]; then
      echo "No compiler found in $CASE_PATH"
      exit 1
    fi
    COMPILER=$CASE_PATH/compiler/compiler
    #wait_for_other_compiling
    make -j$N_CORES CC=$COMPILER > make.log 2>&1 || copy_log_then_exit make.log
    exit 0
  fi

else

CONFIGKEYSDISABLE="
CONFIG_KASAN
CONFIG_KCOV
CONFIG_BUG_ON_DATA_CORRUPTION
CONFIG_DRM_I915
CONFIG_XEN
"
for key in $CONFIGKEYSDISABLE;
do
    config_disable $key
done

# save the dry run log
CLANG=$PROJECT_PATH/tools/llvm/build/bin/clang
make olddefconfig CC=$CLANG
find -type f -name '*.bc' ! -name "timeconst.bc" -delete
make -n CC=$CLANG > clang_log || echo "It's OK"

# First try if wllvm can compile it
export LLVM_COMPILER=clang
export LLVM_COMPILER_PATH=$PROJECT_PATH/tools/llvm/build/bin/
pip3 list | grep wllvm || pip3 install wllvm
make olddefconfig CC=wllvm
ERROR=0
wait_for_other_compiling
make clean CC=wllvm
make -j$N_CORES CC=wllvm > make.log 2>&1 || ERROR=1 && copy_log_then_exit make.log
if [ $ERROR == "0" ]; then
  extract-bc vmlinux
  mv vmlinux.bc one.bc || (find -type f -name '*.bc' ! -name "timeconst.bc" -delete && exit 1)
  exit 0
else
  # back to manual compile and link
  find -type f -name '*.bc' ! -name "timeconst.bc" -delete
  exit 1
fi
fi
exit 1