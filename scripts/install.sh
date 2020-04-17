#!/bin/bash
# Xiaochen Zou 2020, University of California-Riverside
#
# Usage ./install.sh

sudo apt-get update
sudo apt-get -y install git qemu-system-x86 debootstrap flex bison libssl-dev libelf-dev

TOOLS_PATH="$(pwd)/tools"
# Check for image
echo "[+] Building image"
if [ ! -f "$TOOLS_PATH/.stamp/MAKE_IMAGE" ]; then
  if [ ! -d "img" ]; then
    mkdir img
  fi
  cd img
  if [ ! -f "stretch.img" ]; then
    wget https://raw.githubusercontent.com/google/syzkaller/master/tools/create-image.sh -O create-image.sh
    chmod +x create-image.sh
    ./create-image.sh
    touch $TOOLS_PATH/.stamp/MAKE_IMAGE
  fi
  cd ..
fi