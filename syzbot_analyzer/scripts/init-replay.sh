#!/bin/bash
# Xiaochen Zou 2020, University of California-Riverside
#
# Usage ./init-replay.sh SUBFOLER HASH

set -e

PROJECT_PATH="$(pwd)"
SUBFOLDER=$1
HASH=$2 
CASE_PATH="$PROJECT_PATH/work/$SUBFOLDER/$HASH"

if [ -d "$CASE_PATH/.stamp/" ]; then
    rm -r $CASE_PATH/.stamp/
fi