#!/bin/bash
# Xiaochen Zou 2020, University of California-Riverside
#
# Usage ./deploy_linux fixed linux_path patch_path [linux_commit, config_url]

set -ex

function clean_and_jump() {
  make clean
  git stash --all
  git checkout $COMMIT
  curl $CONFIG > .config
  make olddefconfig
}

echo $#
if [ $# -lt 3 ] || [ $# -eq 4 ] || [ $# -gt 5 ]; then
  echo "Usage ./deploy_linux fixed linux_path patch_path [linux_commit, config_url]"
  exit 1
fi

FIXED=$1
LINUX=$2
PATCH=$3/kasan.patch
if [ $# -eq 5 ]; then
  COMMIT=$4
  CONFIG=$5
fi

cd $LINUX
if [ $# -eq 3 ]; then
  patch -p1 -N -R < $PATCH
fi
if [ $# -eq 5 ]; then
  if [ "$FIXED" != "1" ]; then
    CURRENT_HEAD=`git rev-parse HEAD`
    if [ "$CURRENT_HEAD" != "$COMMIT" ]; then
      make clean
      git stash --all
      git checkout $COMMIT
    fi
    curl $CONFIG > .config
  else
    clean_and_jump
  fi
fi
make -j16 || exit 1
exit 0
