#!/bin/bash
# Xiaochen Zou 2020, University of California-Riverside
#
# Usage ./deploy.sh linux_clone_path case_hash linux_commit syzkaller_commit linux_config testcase index catalog image arch gcc_version kasan_patch max_compiling_kernel

set -ex

echo "running deploy.sh"

LATEST="9b1f3e6"

function wait_for_other_compiling() {
  # sometime a process may strave to a long time, seems ok if every case has the same weight
  n=`ps aux | grep "make -j16" | wc -l`
  echo "Wait for other compiling"
  set +x
  while [ $n -ge $(($MAX_COMPILING_KERNEL+1)) ]
  do
    sleep 10
    n=`ps aux | grep "make -j16" | wc -l`
  done
  set -x
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

function copy_log_then_exit() {
  LOG=$1
  cp $LOG $CASE_PATH/$LOG-$COMPILER_VERSION
  exit 1
}

function set_git_config() {
  set +x
  echo "set user.email for git config"
  echo "Input email: "
  read email
  echo "set user.name for git config"
  echo "Input name: "
  read name
  git config --global user.email $email
  git config --global user.name $name
  set -x
}

function build_golang() {
  echo "setup golang environment"
  rm goroot || echo "clean goroot"
  wget https://dl.google.com/go/go1.14.2.linux-amd64.tar.gz
  tar -xf go1.14.2.linux-amd64.tar.gz
  mv go goroot
  if [ ! -d "gopath" ]; then
    mkdir gopath
  fi
  rm go1.14.2.linux-amd64.tar.gz
}

function back_to_newest_version() {
  git checkout -f $LATEST
  cp $PATCHES_PATH/syzkaller-9b1f3e6.patch ./syzkaller.patch
}

function retrieve_proper_patch() {
  git rev-list HEAD | grep $(git rev-parse b5df78d) || back_to_newest_version
  git rev-list b5df78d | grep $(git rev-parse HEAD) || cp $PATCHES_PATH/syzkaller-b5df78d.patch ./syzkaller.patch
  git rev-list 4d4a442 | grep $(git rev-parse HEAD) || cp $PATCHES_PATH/syzkaller-4d4a442.patch ./syzkaller.patch
  git rev-list e503f04 | grep $(git rev-parse HEAD) || cp $PATCHES_PATH/syzkaller-e503f04.patch ./syzkaller.patch
  git rev-list dbd627e | grep $(git rev-parse HEAD) || cp $PATCHES_PATH/syzkaller-dbd627e.patch ./syzkaller.patch
  git rev-list 5de425b | grep $(git rev-parse HEAD) || cp $PATCHES_PATH/syzkaller-5de425b.patch ./syzkaller.patch
  git rev-list 1e9788a | grep $(git rev-parse HEAD) || cp $PATCHES_PATH/syzkaller-1e9788a.patch ./syzkaller.patch
  git rev-list 2cad5aa | grep $(git rev-parse HEAD) || cp $PATCHES_PATH/syzkaller-2cad5aa.patch ./syzkaller.patch
  git rev-list 9b1f3e6 | grep $(git rev-parse HEAD) || cp $PATCHES_PATH/syzkaller-9b1f3e6.patch ./syzkaller.patch
}

if [ $# -ne 13 ]; then
  echo "Usage ./deploy.sh linux_clone_path case_hash linux_commit syzkaller_commit linux_config testcase index catalog image arch gcc_version kasan_patch max_compiling_kernel"
  exit 1
fi

HASH=$2
COMMIT=$3
SYZKALLER=$4
CONFIG=$5
TESTCASE=$6
INDEX=$7
CATALOG=$8
IMAGE=$9
ARCH=${10}
COMPILER_VERSION=${11}
KASAN_PATCH=${12}
MAX_COMPILING_KERNEL=${13}
PROJECT_PATH="$(pwd)"
PKG_NAME="syzbot_analyzer"
CASE_PATH=$PROJECT_PATH/work/$CATALOG/$HASH
PATCHES_PATH=$PROJECT_PATH/$PKG_NAME/patches
echo "Compiler: "$COMPILER_VERSION | grep gcc && \
COMPILER=$PROJECT_PATH/tools/$COMPILER_VERSION/bin/gcc || COMPILER=$PROJECT_PATH/tools/$COMPILER_VERSION/bin/clang

if [ ! -d "tools/$1-$INDEX" ]; then
  echo "No linux repositories detected"
  exit 1
fi

# Check if linux is cloned by git
cd tools/$1-$INDEX
if [ ! -d ".git" ]; then
  echo "This linux repo is not clone by git."
  exit 1
fi

cd ..

# Check for golang environment
export GOPATH=$CASE_PATH/gopath
export GOROOT=`pwd`/goroot
export PATH=$GOROOT/bin:$PATH
echo "[+] Downloading golang"
go version || build_golang

cd $CASE_PATH || exit 1
if [ ! -d ".stamp" ]; then
  mkdir .stamp
fi

if [ ! -d "compiler" ]; then
  mkdir compiler
fi
cd compiler
if [ ! -f "$CASE_PATH/compiler/compiler" ]; then
  ln -s $COMPILER ./compiler
fi

#Building for syzkaller
echo "[+] Building syzkaller"
if [ ! -f "$CASE_PATH/.stamp/BUILD_SYZKALLER" ]; then
  if [ -d "$GOPATH/src/github.com/google/syzkaller" ]; then
    rm -rf $GOPATH/src/github.com/google/syzkaller
  fi
  mkdir -p $GOPATH/src/github.com/google/ || echo "Dir exists"
  cd $GOPATH/src/github.com/google/
  git clone https://github.com/google/syzkaller.git
  #go get -u -d github.com/google/syzkaller/prog
  #fi
  cd $GOPATH/src/github.com/google/syzkaller || exit 1
  make clean
  git stash --all || set_git_config
  git checkout -f 9b1f3e665308ee2ddd5b3f35a078219b5c509cdb
  #git checkout -
  #retrieve_proper_patch
  cp $PATCHES_PATH/syzkaller-9b1f3e6.patch ./syzkaller.patch
  patch -p1 -i syzkaller.patch
  #rm -r executor
  #cp -r $PROJECT_PATH/tools/syzkaller/executor ./executor
  make TARGETARCH=$ARCH TARGETVMARCH=amd64
  if [ ! -d "workdir" ]; then
    mkdir workdir
  fi
  touch $CASE_PATH/.stamp/BUILD_SYZKALLER
fi
curl $TESTCASE > $GOPATH/src/github.com/google/syzkaller/workdir/testcase-$HASH

cd $CASE_PATH || exit 1
echo "[+] Copy image"
if [ ! -d "$CASE_PATH/img" ]; then
  mkdir -p $CASE_PATH/img
fi
cd img
if [ ! -f "$CASE_PATH/img/stretch.img" ]; then
  ln -s $PROJECT_PATH/tools/img/$IMAGE.img ./stretch.img
fi
if [ ! -f "$CASE_PATH/img/stretch.img.key" ]; then
  ln -s $PROJECT_PATH/tools/img/$IMAGE.img.key ./stretch.img.key
fi
cd ..

#Building kernel
echo "[+] Building kernel"
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
if [ ! -f "$CASE_PATH/.stamp/BUILD_KERNEL" ]; then
  cd linux
  if [ -f "THIS_KERNEL_IS_BEING_USED" ]; then
    echo "This kernel is using by other thread"
    exit 1
  fi
  git stash
  git clean -fdx -e THIS_KERNEL_IS_BEING_USED > /dev/null
  #make clean CC=$COMPILER
  #git stash --all || set_git_config
  git checkout -f $COMMIT || (git pull https://github.com/torvalds/linux.git master > /dev/null 2>&1 && git checkout -f $COMMIT)
  if [ "$KASAN_PATCH" == "1" ]; then
    cp $PATCHES_PATH/kasan.patch ./
    patch -p1 -i kasan.patch
  fi
  #Add a rejection detector in future
  curl $CONFIG > .config

#  CONFIGKEYSDISABLE="
#CONFIG_BUG_ON_DATA_CORRUPTION
#CONFIG_KASAN_INLINE
#"

#  CONFIGKEYSENABLE="
#CONFIG_KASAN_OUTLINE
#"

CONFIGKEYSENABLE="
CONFIG_HAVE_ARCH_KASAN
CONFIG_KASAN
CONFIG_KASAN_OUTLINE
CONFIG_DEBUG_INFO
CONFIG_FRAME_POINTER
CONFIG_UNWINDER_FRAME_POINTER"

CONFIGKEYSDISABLE="
CONFIG_BUG_ON_DATA_CORRUPTION
CONFIG_KASAN_INLINE
CONFIG_RANDOMIZE_BASE
CONFIG_PANIC_ON_OOPS
CONFIG_X86_SMAP
"
#CONFIG_SOFTLOCKUP_DETECTOR
#CONFIG_LOCKUP_DETECTOR
#CONFIG_HARDLOCKUP_DETECTOR
#CONFIG_DETECT_HUNG_TASK
#CONFIG_WQ_WATCHDOG
#CONFIG_ARCH_HAS_KCOV
#CONFIG_KCOV
#CONFIG_KCOV_INSTRUMENT_ALL
#CONFIG_PROVE_LOCKING
#CONFIG_DEBUG_RT_MUTEXES
#CONFIG_DEBUG_SPINLOCK
#CONFIG_DEBUG_MUTEXES
#CONFIG_DEBUG_WW_MUTEX_SLOWPATH
#CONFIG_DEBUG_RWSEMS
#CONFIG_DEBUG_LOCK_ALLOC
#CONFIG_DEBUG_ATOMIC_SLEEP
#CONFIG_DEBUG_LIST
  
  for key in $CONFIGKEYSDISABLE;
  do
    config_disable $key
  done

  for key in $CONFIGKEYSENABLE;
  do
    config_enable $key
  done

  make olddefconfig CC=$COMPILER
  if [ $MAX_COMPILING_KERNEL != "-1" ]; then
    wait_for_other_compiling
  fi 
  make -j16 CC=$COMPILER > make.log 2>&1 || copy_log_then_exit make.log
  cp .config $CASE_PATH/config
  touch THIS_KERNEL_IS_BEING_USED
  touch $CASE_PATH/.stamp/BUILD_KERNEL
fi

exit 0
