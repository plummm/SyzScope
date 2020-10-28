#!/bin/bash
# Xiaochen Zou 2020, University of California-Riverside
#
# Usage ./run-vm.sh image_path linux_path ssh_port

set -ex

if [ $# -ne 3 ]; then
  echo "Usage ./run-vm.sh image_path linux_path ssh_port"
  exit 1
fi

IMAGE=$1
LINUX=$2
PORT=$3

qemu-system-x86_64 \
  -m 2G \
  -smp 2 \
  -net nic,model=e1000 \
  -enable-kvm -cpu host \
  -net user,host=10.0.2.10,hostfwd=tcp::$PORT-:22 \
  -display none -serial stdio -no-reboot \
  -hda $IMAGE \
  -kernel $LINUX/arch/x86_64/boot/bzImage \
  -append "console=ttyS0 net.ifnames=0 root=/dev/sda printk.synchronous=1"
