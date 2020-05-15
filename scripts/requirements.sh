#!/bin/bash
# Xiaochen Zou 2020, University of California-Riverside
#
# Usage ./install.sh

sudo apt-get update
sudo apt-get -y install git qemu-system-x86 debootstrap flex bison libssl-dev libelf-dev

if [ ! -d "work/completed" ]; then
  mkdir -p work/completed
fi

if [ ! -d "work/incomplete" ]; then
  mkdir -p work/incomplete
fi

TOOLS_PATH="$(pwd)/tools"
# Check for image
echo "[+] Building image"
cd $TOOLS_PATH
if [ ! -f "$TOOLS_PATH/.stamp/MAKE_IMAGE" ]; then
  if [ ! -d "img" ]; then
    mkdir img
  fi
  cd img
  if [ ! -f "stretch.img" ]; then
    wget https://storage.googleapis.com/syzkaller/stretch.img
    wget https://storage.googleapis.com/syzkaller/stretch.img.key
    chmod 400 stretch.img.key
    wget https://storage.googleapis.com/syzkaller/wheezy.img
    wget https://storage.googleapis.com/syzkaller/wheezy.img.key
    chmod 400 wheezy.img.key
    touch $TOOLS_PATH/.stamp/MAKE_IMAGE
  fi
  cd ..
fi