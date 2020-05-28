#!/bin/bash
# Xiaochen Zou 2020, University of California-Riverside
#
# Usage ./deploy_linux fixed linux_path patch_path [linux_commit, config_url]

set -ex

echo "running deploy_linux.sh"

function clean_and_jump() {
  git stash --all
  git checkout $COMMIT
}

function copy_log_then_exit() {
  LOG=$1
  cp $LOG $CASE_PATH
  exit 1
}

if [ $# -lt 3 ] || [ $# -eq 4 ] || [ $# -gt 5 ]; then
  echo "Usage ./deploy_linux fixed linux_path project_path [linux_commit, config_url]"
  exit 1
fi

FIXED=$1
LINUX=$2
PATCH=$3/patches/kasan.patch
GCC=$3/tools/gcc/bin/gcc
if [ $# -eq 5 ]; then
  COMMIT=$4
  CONFIG=$5
fi

cd $LINUX
if [ $# -eq 3 ]; then
  #patch -p1 -N -R < $PATCH
  echo "no more patch"
fi
if [ $# -eq 5 ]; then
  if [ "$FIXED" != "1" ]; then
    CURRENT_HEAD=`git rev-parse HEAD`
    if [ "$CURRENT_HEAD" != "$COMMIT" ]; then
      make clean
      git stash --all
      git pull https://github.com/torvalds/linux.git master > /dev/null 2>&1
      git checkout $COMMIT
    fi
    curl $CONFIG > .config
  else
    make clean
    git stash --all
    git format-patch -1 $COMMIT --stdout > fixed.patch
    patch -p1 -N -i fixed.patch || exit 1
    curl $CONFIG > .config
    make olddefconfig CC=$GCC
  fi
fi
make -j16 CC=$GCC > make.log || copy_log_then_exit make.log
exit 0
