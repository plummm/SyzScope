#!/bin/bash
# Xiaochen Zou 2020, University of California-Riverside
#
# Usage ./requirements.sh

sudo apt-get update
sudo apt-get -y install git qemu-system-x86 debootstrap flex bison libssl-dev libelf-dev

if [ ! -d "work/completed" ]; then
  mkdir -p work/completed
fi

if [ ! -d "work/incomplete" ]; then
  mkdir -p work/incomplete
fi

TOOLS_PATH="$(pwd)/tools"
if [ ! -d "$TOOLS_PATH/.stamp" ]; then
  mkdir -p $TOOLS_PATH/.stamp
fi
# Check for image
echo "[+] Building image"
cd $TOOLS_PATH
if [ ! -f "$TOOLS_PATH/.stamp/MAKE_IMAGE" ]; then
  if [ ! -d "img" ]; then
    mkdir img
  fi
  cd img
  if [ ! -f "stretch.img" ]; then
    wget https://storage.googleapis.com/syzkaller/stretch.img > /dev/null
    wget https://storage.googleapis.com/syzkaller/stretch.img.key > /dev/null
    chmod 400 stretch.img.key
    wget https://storage.googleapis.com/syzkaller/wheezy.img > /dev/null
    wget https://storage.googleapis.com/syzkaller/wheezy.img.key > /dev/null
    chmod 400 wheezy.img.key
    touch $TOOLS_PATH/.stamp/MAKE_IMAGE
  fi
  cd ..
fi

echo "[+] Building gcc"
if [ ! -f "$TOOLS_PATH/.stamp/MAKE_GCC" ]; then
  wget https://storage.googleapis.com/syzkaller/gcc-7.tar.gz > /dev/null
  tar xzf gcc-7.tar.gz
  mv gcc gcc-7
  rm gcc-7.tar.gz

  wget https://storage.googleapis.com/syzkaller/gcc-8.0.1-20180301.tar.gz > /dev/null
  tar xzf gcc-8.0.1-20180301.tar.gz
  mv gcc gcc-8.0.1-20180301
  rm gcc-8.0.1-20180301.tar.gz

  wget https://storage.googleapis.com/syzkaller/gcc-8.0.1-20180412.tar.gz > /dev/null
  tar xzf gcc-8.0.1-20180412.tar.gz
  mv gcc gcc-8.0.1-20180412
  rm gcc-8.0.1-20180412.tar.gz

  wget https://storage.googleapis.com/syzkaller/gcc-9.0.0-20181231.tar.gz > /dev/null
  tar xzf gcc-9.0.0-20181231.tar.gz
  mv gcc gcc-9.0.0-20181231
  rm gcc-9.0.0-20181231.tar.gz

  wget https://storage.googleapis.com/syzkaller/gcc-10.1.0-syz.tar.xz > /dev/null
  tar xf gcc-10.1.0-syz.tar.xz
  mv gcc-10 gcc-10.1.0-20200507
  rm gcc-10.1.0-syz.tar.xz


  #This is for gcc-9
  #if [ ! -f "/usr/lib/x86_64-linux-gnu/libmpfr.so.4" ]; then
  #  sudo ln -s /usr/lib/x86_64-linux-gnu/libmpfr.so.6 /usr/lib/x86_64-linux-gnu/libmpfr.so.4
  #fi
  touch $TOOLS_PATH/.stamp/MAKE_GCC
  cd ..
fi

#BUG: If multiple instances are running, may clean up others' flag
echo "[+] Clean unfinished jobs"
rm linux-*/THIS_KERNEL_HAS_BEEN_USED || echo "All set"