#!/bin/bash
# Xiaochen Zou 2020, University of California-Riverside
#
# Usage ./deploy.sh linux_clone_path case_hash linux_commit syzkaller_commit linux_config testcase index catalog image arch

set -ex

echo "running deploy.sh"

LATEST="9b1f3e6"

function copy_log_then_exit() {
  LOG=$1
  cp $LOG $CASE_PATH
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
  git checkout $LATEST
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

if [ $# -ne 10 ]; then
  echo "Usage ./deploy.sh linux_clone_path case_hash linux_commit syzkaller_commit linux_config testcase index catalog image arch"
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
PROJECT_PATH="$(pwd)"
CASE_PATH=$PROJECT_PATH/work/$CATALOG/$HASH
PATCHES_PATH=$PROJECT_PATH/patches
GCC=$PROJECT_PATH/tools/gcc/bin/gcc
export CC=$GCC

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

if [ ! -d ".stamp" ]; then
  mkdir .stamp
fi

#Building for syzkaller
echo "[+] Building syzkaller"
if [ ! -f "$CASE_PATH/.stamp/BUILD_SYZKALLER" ]; then
  if [ -d "$GOPATH/src/github.com/google/syzkaller" ]; then
    rm -rf $GOPATH/src/github.com/google/syzkaller
  fi
  go get -u -d github.com/google/syzkaller/prog
  #fi
  cd $GOPATH/src/github.com/google/syzkaller || exit 1
  make clean
  git stash --all || set_git_config
  git checkout 9b1f3e665308ee2ddd5b3f35a078219b5c509cdb
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
  if [ -f "THIS_KERNEL_HAS_BEEN_USED" ]; then
    echo "This kernel is using by other thread"
    exit 1
  fi
  git stash
  make clean
  git stash --all || set_git_config
  git pull https://github.com/torvalds/linux.git master > pull.log || copy_log_then_exit pull.log
  git checkout $COMMIT
  #cp $PATCHES_PATH/kasan.patch ./
  #patch -p1 -i kasan.patch
  #Add a rejection detector in future
  curl $CONFIG > .config
  make olddefconfig
  make -j16 > make.log 2>&1 || copy_log_then_exit make.log
  touch THIS_KERNEL_HAS_BEEN_USED
  touch $CASE_PATH/.stamp/BUILD_KERNEL
fi

exit 0
