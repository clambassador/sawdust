#!/bin/bash

MY_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
source $MY_DIR/common-local.sh

LOG_PARALLEL_PARSE_LOCK=/tmp/log-parallel-parse.lock
function unlocklogs() {
    echo "unlocking"
    rm -f $LOG_PARALLEL_PARSE_LOCK
}


BASE_CFG=$(basename $SAWDUST_CFG)
function sawdustcleanup() {
    if [ -f ./$BASE_CFG ]; then
        rm -f ./$BASE_CFG
    fi

    unlocklogs
}

if [ ! -f $LOG_PARALLEL_PARSE_LOCK ]; then
    trap unlocklogs EXIT
    touch $LOG_PARALLEL_PARSE_LOCK

    cd $MY_DIR

    if [ $# -eq 2 ]; then
        LOGS_DIR=$(realpath $1)
        OUT_DIR=$(realpath $2)

        TIMESTAMP=$(date +%Y%m%d%H%M)
        TRANSMITS=$OUT_DIR/$TIMESTAMP.transmissions
        PERMS=$OUT_DIR/$TIMESTAMP.permissions
        FILES=$OUT_DIR/$TIMESTAMP.fileaccess
        EXECS=$OUT_DIR/$TIMESTAMP.execcommands

        PACKETS_PATH=$OUT_DIR/packets-$TIMESTAMP
        mkdir -p $PACKETS_PATH

        # Guarantee that output files exist
        touch $TRANSMITS
        touch $PERMS
        touch $FILES
        touch $EXECS

        # Make sure the sawdust config is in the current directory
        if [ ! -f ./$BASE_CFG ]; then
            cp $SAWDUST_CFG ./$BASE_CFG
            trap sawdustcleanup EXIT

            if [ -f ./$BASE_CFG ]; then
                sed -i "s,string packetdb.*,string packetdb $PACKETS_PATH," $BASE_CFG > /dev/null
            fi
        fi

        # Find unprocessed logs that haven't been touched in the last 30 minutes (to filter out runs-in-progress)
        FILES_PROCESSED=$OUT_DIR/$TIMESTAMP.filesprocessed
        #find $LOGS_DIR -name "*.log" -mmin +30 -exec bash -c 'LOG_DIR=$(dirname {}); test ! -f $LOG_DIR/processed.status' \; -print > $FILES_PROCESSED
        find $LOGS_DIR -name "*.log" -exec bash -c 'LOG_DIR=$(dirname {}); test ! -f $LOG_DIR/processed.status' \; -print > $FILES_PROCESSED

        # Parse permission and file access logs in parallel
        cat $FILES_PROCESSED | parallel --no-notice ./logs-procpermissions.sh > $PERMS
        cat $FILES_PROCESSED | parallel --no-notice ./logs-procdmesg.sh > $FILES
        cat $FILES_PROCESSED | parallel --no-notice ./logs-procexec.sh > $EXECS

        # Parse packets serially (leveldb is not thread-safe)
        cat $FILES_PROCESSED | xargs -I {} ./logs-procpackets.sh {} > $TRANSMITS
    else
        (>&2 echo 'USAGE: log-parallel-parse.sh <input logs directory> <output dir>')
    fi

else
    (>&2 echo "log-parallel-parse currently locked ($LOG_PARALLEL_PARSE_LOCK exists)")
fi

