#!/bin/bash
# Xiaochen Zou 2020, University of California-Riverside
#
# Usage ./deploy_linux fixed linux_path patch_path [linux_commit, config_url, mode]

set -ex

echo "running deploy_linux.sh"

function clean_and_jump() {
  git stash --all
  git checkout -f $COMMIT
}

function copy_log_then_exit() {
  LOG=$1
  cp $LOG $CASE_PATH/$LOG-deploy_linux
  exit 1
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

if [ $# -ne 5 ] && [ $# -ne 8 ]; then
  echo "Usage ./deploy_linux gcc_version fixed linux_path package_path max_compiling_kernel [linux_commit, config_url, mode]"
  exit 1
fi

COMPILER_VERSION=$1
FIXED=$2
LINUX=$3
PATCH=$4/patches/kasan.patch
MAX_COMPILING_KERNEL=$5
N_CORES=$((`nproc` / $MAX_COMPILING_KERNEL))
echo "Compiler: "$COMPILER_VERSION | grep gcc && \
COMPILER=$4/tools/$COMPILER_VERSION/bin/gcc || COMPILER=$4/tools/$COMPILER_VERSION/bin/clang

if [ $# -eq 8 ]; then
  COMMIT=$6
  CONFIG=$7
  MODE=$8
fi

cd $LINUX
cd ..
CASE_PATH=`pwd`
cd linux
if [ $# -eq 5 ]; then
  #patch -p1 -N -R < $PATCH
  echo "no more patch"
fi
if [ $# -eq 8 ]; then
  if [ "$FIXED" != "1" ]; then
    git stash
    git clean -fdx -e THIS_KERNEL_IS_BEING_USED > /dev/null
    CURRENT_HEAD=`git rev-parse HEAD`
    if [ "$CURRENT_HEAD" != "$COMMIT" ]; then
      #make clean CC=$COMPILER
      #git stash --all
      git checkout -f $COMMIT || (git pull https://github.com/torvalds/linux.git master > /dev/null 2>&1 && git checkout -f $COMMIT)
    fi
    curl $CONFIG > .config
  else
    git format-patch -1 $COMMIT --stdout > fixed.patch
    patch -p1 -N -i fixed.patch || exit 1
    curl $CONFIG > .config
  fi
fi

# Panic on data corruption may stop the fuzzing session
if [ "$MODE" == "0" ]; then
CONFIGKEYSDISABLE="
CONFIG_BUG_ON_DATA_CORRUPTION
CONFIG_KASAN_INLINE
CONFIG_KCOV
"

CONFIGKEYSENABLE="
CONFIG_KASAN_OUTLINE
"
fi

if [ "$MODE" == "1" ]; then
CONFIGKEYSENABLE="
CONFIG_HAVE_ARCH_KASAN
CONFIG_KASAN
CONFIG_KASAN_OUTLINE
CONFIG_DEBUG_INFO
CONFIG_FRAME_POINTER
CONFIG_UNWINDER_FRAME_POINTER"

CONFIGKEYSDISABLE="
CONFIG_KASAN_INLINE
CONFIG_RANDOMIZE_BASE
CONFIG_SOFTLOCKUP_DETECTOR
CONFIG_LOCKUP_DETECTOR
CONFIG_HARDLOCKUP_DETECTOR
CONFIG_DETECT_HUNG_TASK
CONFIG_WQ_WATCHDOG
CONFIG_PANIC_ON_OOPS
CONFIG_X86_SMAP
CONFIG_PROVE_LOCKING
CONFIG_DEBUG_RT_MUTEXES
CONFIG_DEBUG_SPINLOCK
CONFIG_DEBUG_MUTEXES
CONFIG_DEBUG_WW_MUTEX_SLOWPATH
CONFIG_DEBUG_RWSEMS
CONFIG_DEBUG_LOCK_ALLOC
CONFIG_DEBUG_ATOMIC_SLEEP
CONFIG_DEBUG_LIST
CONFIG_ARCH_HAS_KCOV
CONFIG_KCOV
CONFIG_KCOV_INSTRUMENT_ALL
"
fi

for key in $CONFIGKEYSDISABLE;
do
  config_disable $key
done

for key in $CONFIGKEYSENABLE;
do
  config_enable $key
done

make olddefconfig CC=$COMPILER
make -j$N_CORES CC=$COMPILER > make.log 2>&1 || copy_log_then_exit make.log
exit 0
