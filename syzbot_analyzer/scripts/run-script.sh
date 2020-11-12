#!/bin/bash
# Xiaochen Zou 2020, University of California-Riverside
#
# Usage ./run-script.sh command ssh_port image_path case_path

echo "running run-script.sh"

if [ $# -ne 4 ]; then
    echo "Usage ./run-script.sh command ssh_port image_path case_path"
    exit 1
fi

COMMAND=$1
PORT=$2
IMAGE_PATH=$3
CASE_PATH=$4

RAW_COMMAND=`echo $COMMAND | sed -E "s/ -enable=[a-z_]+(,[a-z_]+)*//g"`

cd $CASE_PATH/poc || exit 1
cat << EOF > run.sh
#!/bin/bash
set -ex

# cprog somehow work not as good as prog, an infinite loop even blocks the execution of syz-execprog
#if [ -f "./poc" ]; then
#    ./poc
#fi

for i in {1..10}
do
    ${COMMAND} || ${RAW_COMMAND}
    
    #Sometimes the testcase is not required to repeat, but we still give a shot
    sleep 5
done
EOF

CMD="scp -F /dev/null -o UserKnownHostsFile=/dev/null \
    -o BatchMode=yes -o IdentitiesOnly=yes -o StrictHostKeyChecking=no \
    -i $IMAGE_PATH/stretch.img.key -P $PORT ./run.sh root@localhost:/root"
$CMD
echo $CMD > run-script.sh
exit 0