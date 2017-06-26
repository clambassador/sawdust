#!/bin/bash

function procpackets() {
    if [ $# -eq 1 ]; then
        LOG_FILE=$1
        DEV_FILE=${LOG_FILE%.log}.device
        HWID=$(grep 'hwid' $DEV_FILE | cut -d ' ' -f2)

        ID_FILE=id_search.csv
        ./sawdust $LOG_FILE $DEV_FILE $HWID id_search > $ID_FILE
        python id_search.py $ID_FILE
        rm $ID_FILE
    fi
}

function procpermissions() {
    if [ $# -eq 1 ]; then
        LOG_FILE=$1

        ./permission_processor $LOG_FILE
    fi
}

if [ $# -eq 3 ]; then
    LOGS_DIR=`realpath $1`
    TRANSMITS=`realpath $2`
    PERMS=`realpath $3`

    SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
    pushd $SCRIPT_DIR

    for LOG_FILE in `find $LOGS_DIR -name "*.log"`; do
        LOG_DIR=`dirname $LOG_FILE`
        PROCESSED_MARK=$LOG_DIR/processed.status

        # Ignore logs that have been marked as processed
        if [ ! -f $PROCESSED_MARK ]; then

            # Only process logs with a 'logcat start' line
            if grep -q 'logcat start' $LOG_FILE; then
                procpackets $LOG_FILE >> $TRANSMITS
                procpermissions $LOG_FILE >> $PERMS
                touch $PROCESSED_MARK
            else
                (>&2 echo "SKIPPING $LOG_FILE , no logcat lines")
            fi

        fi
    done

else
    (>&2 echo 'USAGE: process.sh <input logs directory> <output transmissions csv> <output permissions csv>')

fi
