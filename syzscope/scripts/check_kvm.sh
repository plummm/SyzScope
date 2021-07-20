#!/bin/bash
# Xiaochen Zou 2020, University of California-Riverside

set -e

function add_user_to_kvm_group() {
    echo "$(whoami) is not in kvm group"
    echo "Adding $(whoami) to kvm group"
    set -x
    sudo usermod -a -G kvm $(whoami)
    set +x
    echo "Re-login and run SyzScope again"
    exit 1
}

if [ ! -e "/dev/kvm" ]; then
  echo "This machine do not support KVM. SyzScope cannot run on it."
  exit 1
fi

groups $(whoami) | grep kvm || add_user_to_kvm_group
echo "KVM is ready to go"
exit 0