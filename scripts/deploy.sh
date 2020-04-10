#!/bin/bash
# Xiaochen Zou 2020, University of California-Riverside
#
# Usage ./deploy.sh linux_clone_path case_hash linux_commit syzkaller_commit linux_config testcase

set -e

function set_git_config() {
  echo "set user.email for git config"
  echo "Input email: "
  read email
  echo "set user.name for git config"
  echo "Input name: "
  read name
  git config --global user.email $email
  git config --global user.name $name
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

if [ $# -ne 6 ]; then
  echo "Usage ./deploy.sh linux_clone_path case_hash linux_commit syzkaller_commit linux_config testcase"
  exit 1
fi

sudo apt-get update

HASH=$2
COMMIT=$3
SYZKALLER=$4
CONFIG=$5
TESTCASE=$6
PATCHES_PATH="$(pwd)/patches"

if [ ! -d "tools/$1" ]; then
  echo "No linux repositories detected"
  exit 1
fi

TOOLS_PATH="$(pwd)/tools"
# Check if linux is cloned by git
cd tools/$1
if [ ! -d ".git" ]; then
  echo "This linux repo is not clone by git."
  exit 1
fi

cd ..

# Check for golang environment
export GOPATH=`pwd`/gopath
export GOROOT=`pwd`/goroot
export PATH=$GOROOT/bin:$PATH
echo "[+] Downloading golang"
go version || build_golang

if [ ! -d ".stamp" ]; then
  mkdir .stamp
fi

# Check for image
echo "[+] Building image"
if [ ! -f "$TOOLS_PATH/.stamp/MAKE_IMAGE" ]; then
  if [ ! -d "img" ]; then
    mkdir img
  fi
  cd img
  IMAGE=$(pwd)
  if [ ! -f "stretch.img" ]; then
    sudo apt-get -y install debootstrap
    wget https://raw.githubusercontent.com/google/syzkaller/master/tools/create-image.sh -O create-image.sh
    chmod +x create-image.sh
    sudo ./create-image.sh
    touch $TOOLS_PATH/.stamp/MAKE_IMAGE
  fi
fi

#Back to work directory
cd ..
if [ ! -d "work" ]; then
  mkdir work
fi
cd work

if [ ! -d $HASH ]; then
 mkdir $HASH
fi
cd $HASH || exit 1

#Building kernel
echo "[+] Building kernel"
if [ ! -f "$TOOLS_PATH/.stamp/BUILD_KERNEL" ]; then
  sudo apt-get -y install flex bison libssl-dev
  ln -s ../../tools/$1 ./linux
  cd linux
  KERNEL_PATH=$(pwd)
  git stash --all || set_git_config
  git checkout $COMMIT
  cp $PATCHES_PATH/kasan.patch ./
  patch -p1 -i kasan.patch
  #Add a rejection detector in future
  curl $CONFIG > .config
  make -j16
  touch $TOOLS_PATH/.stamp/BUILD_KERNEL
fi

#Building for syzkaller
echo "[+] Building syzkaller"
if [ ! -f "$TOOLS_PATH/.stamp/BUILD_SYZKALLER" ]; then
  NEW_VERSION=0
  go get -u -d github.com/google/syzkaller/...
  cd $GOPATH/src/github.com/google/syzkaller || exit 1
  git stash --all || set_git_config
  git checkout $SYZKALLER
  git rev-list 9b1f3e6 | grep $(git rev-parse HEAD) || NEW_VERSION=1
  if [[ "$NEW_VERSION" -eq 1 ]]; then
    cp $PATCHES_PATH/syzkaller_new.patch ./syzkaller.patch
  else
    cp $PATCHES_PATH/syzkaller_old.patch ./syzkaller.patch
  fi
  patch -p1 -i syzkaller.patch
  make
  if [ ! -d "workdir" ]; then
    mkdir workdir
  fi
  echo $TESTCASE > workdir/testcase-$HASH
  touch $TOOLS_PATH/.stamp/BUILD_SYZKALLER
fi

echo -e "\n\e[31mPlace following commands in your \e[33m.bash_profile/.bashrc/.zshrc \e[31mor other startup script\n\e[39m"
echo "export GOPATH=$GOPATH"
echo "export GOROOT=$GOROOT"
echo "export PATH=\$GOROOT/bin:\$PATH"
exit 0