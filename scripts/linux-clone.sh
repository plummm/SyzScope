#!/bin/bash
# Xiaochen Zou 2020, University of California-Riverside
#
# Usage ./linux-clone linux_clone_path

if [ $# -ne 1 ]; then
  echo "Usage ./linux-clone linux_clone_path index"
  exit 1
fi

sudo apt-get update
sudo apt-get -y install git

mkdir tools || echo "Directory exists\n"
cd tools || exit 1
git clone https://github.com/torvalds/linux.git $1-$2
echo "Linux cloned to $1-$2"