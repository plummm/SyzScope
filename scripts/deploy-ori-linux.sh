#!/bin/bash
# Xiaochen Zou 2020, University of California-Riverside
#
# Usage ./deploy-ori-linux linux_path patch_path [linux_commit, config_url]

set -ex

echo $#
if [ $# -lt 2 ] || [ $# -eq 3 ] || [ $# -gt 4 ]; then
  echo "Usage ./deploy-ori-linux linux_path patch_path [linux_commit, config_url]"
  exit 1
fi

LINUX=$1
PATCH=$2/kasan.patch
if [ $# -eq 4 ]; then
  COMMIT=$3
  CONFIG=$4
fi

cd $LINUX
if [ $# -eq 2 ]; then
  patch -p1 -N -R < $PATCH
fi
if [ $# -eq 4 ]; then
  CURRENT_HEAD=`git rev-parse HEAD`
  if [ "$CURRENT_HEAD" != "$COMMIT" ]; then
    make clean
    git stash --all
    git checkout $COMMIT
  fi
  curl $CONFIG > .config
fi
make -j16 || exit 1
exit 0
