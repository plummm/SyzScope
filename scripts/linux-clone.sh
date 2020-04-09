#!/bin/bash
# Xiaochen Zou 2020, University of California-Riverside
#
# Usage ./linux-clone linux_clone_path

if [ $# -ne 1 ]; then
  echo "Usage ./linux-clone linux_clone_path"
  exit 1
if

sudo apt-get update
sudo apt-get -y install git

mkdir tools
cd tools
git clone https://github.com/torvalds/linux.git $1
echo "Linux cloned to $1"