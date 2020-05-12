#!/bin/bash
# Xiaochen Zou 2020, University of California-Riverside
#
# Usage ./run-script.sh command ssh_port image_path case_path
if [ $# -ne 4 ]; then
    echo "Usage ./run-script.sh command ssh_port image_path case_path"
    exit 1
fi

COMMAND=$1
PORT=$2
IMAGE_PATH=$3
CASE_PATH=$4

cd $CASE_PATH/poc || exit 1
cat << EOF > run.sh
#!/bin/bash

if [ -f "./poc" ]; then
    ./poc
fi
sleep 1
${COMMAND}
EOF

scp -F /dev/null -o UserKnownHostsFile=/dev/null \
    -o BatchMode=yes -o IdentitiesOnly=yes -o StrictHostKeyChecking=no \
    -i $IMAGE_PATH/stretch.id_rsa -P $PORT ./run.sh root@localhost:/root
exit 0