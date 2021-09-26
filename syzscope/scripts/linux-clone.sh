#!/bin/bash
# Xiaochen Zou 2020, University of California-Riverside
#
# Usage ./linux-clone linux_clone_path

echo "running linux-clone.sh"

if [ $# -ne 2 ]; then
  echo "Usage ./linux-clone linux_clone_path index"
  exit 1
fi

if [ -d "tools/$1-$2" ]; then
  exit 0
fi
if [ ! -d "tools" ]; then
  mkdir tools
fi
cd tools || exit 1
if [ ! -d "linux-0" ]; then
  git clone https://github.com/torvalds/linux.git $1-$2
else
  cp -r linux-0 $1-$2
fi
echo "Linux cloned to $1-$2"