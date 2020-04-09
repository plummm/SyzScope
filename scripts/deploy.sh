#!/bin/bash
# Xiaochen Zou 2020, University of California-Riverside
#
# Usage ./deploy.sh linux_clone_path case_hash linux_commit syzkaller_commit linux_config testcase

set -ex

if [ $# -ne 6 ]; then
  echo "Usage ./deploy.sh linux_clone_path case_hash linux_commit syzkaller_commit linux_config testcase"
  exit 1
fi

HASH=$2
COMMIT=$3
SYZKALLER=$4
CONFIG=$5
TESTCASE=$6
PATCHES_PATH="$(pwd)/patches"

if [ ! -d "tools/$1" ]; then
  echo "No linux repositories detected\n"
  exit 1
fi

# Check if linux is cloned by git
cd tools/$1
if [ ! -d ".git" ]; then
  echo "This linux repo is not clone by git.\n"
  exit 1
fi

cd ..

# Check for golang environment
export GOPATH=`pwd`/gopath
export GOROOT=`pwd`/goroot
export PATH=$GOPATH/bin:$PATH
export PATH=$GOROOT/bin:$PATH
go version || echo "setup golang environment\n" && \
wget https://dl.google.com/go/go1.14.2.linux-amd64.tar.gz && \
tar -xf go1.14.2.linux-amd64.tar.gz && \
mv go goroot && \
mkdir gopath && \
rm go1.14.2.linux-amd64.tar.gz

# Check for image
if [ ! -f ".stamp/MAKE_IMAGE" ]; then
  if [ ! -d "img" ]; then
    mkdir img
  fi
  cd img
  IMAGE=$(pwd)
  if [ ! -f "stretch.img" ]; then
    echo "Making image\n"
    sudo apt-get update
    sudo apt-get -y install debootstrap
    wget https://raw.githubusercontent.com/google/syzkaller/master/tools/create-image.sh -O create-image.sh
    chmod +x create-image.sh
    sudo ./create-image.sh
    touch .stamp/MAKE_IMAGE
  fi
fi

#Back to work directory
cd ..
if [ ! -d "work" ]; then
  mkdir work
fi
cd work

mkdir $HASH
cd $HASH

#Building kernel
echo "Building kernel\n"
if [ ! -f ".stamp/BUILD_KERNEL" ]; then
  ln -s ../../tools/$1 ./linux
  cp $PATCHES_PATH/kasan.patch ./linux
  cd linux
  KERNEL_PATH=$(pwd)
  git stash -all
  git checkout $COMMIT
  patch -p1 -i kasan.patch
  #Add a rejection detector in future
  curl $CONFIG > .config
  make -j16
  touch .stamp/BUILD_KERNEL
fi

#Checking for syzkaller
cd $GOPATH/src/github.com/google
if [ ! -d "syzkaller" ]; then
  echo "Downloading syzkaller"
  go get -u -d github.com/google/syzkaller/...
fi
cd syzkaller
git stash -all
git checkout $SYZKALLER
cp $PATCHES_PATH/syzkaller.patch ./
patch -p1 -i syzkaller.patch

if [ ! -d "workdir" ]; then
  mkdir workdir
fi

echo $TESTCASE > workdir/testcase-$HASH
export PATH=$IMAGE/bin:$PATH
export PATH=$KERNEL_PATH/bin:$PATH
SYZKALLER_PATH=$GOPATH/src/github.com/google/syzkaller
exit $SYZKALLER_PATH