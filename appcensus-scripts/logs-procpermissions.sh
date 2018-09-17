#!/bin/bash

DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
source $DIR/common-local.sh

if [ $# -eq 1 ]; then
    LOG_FILE=$1

    $PERM_SCRIPT $LOG_FILE
fi
