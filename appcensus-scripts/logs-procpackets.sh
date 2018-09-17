#!/bin/bash

DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
source $DIR/common-local.sh

function formatline() {
    LOG_PATH=$1
    LABEL=$2

    grep -e "I $LABEL\\s*:" $LOG_PATH | sed "s,^.* I $LABEL,$LABEL," | sed "s,^$LABEL *:,$LABEL:,"
}

function devfileregen() {
    LOG_PATH=$1

    formatline $LOG_PATH 'aaid'
    formatline $LOG_PATH 'androidid'
    formatline $LOG_PATH 'email'
    formatline $LOG_PATH 'fingerprint'
    formatline $LOG_PATH 'geolatlon'
    formatline $LOG_PATH 'gsfid'
    formatline $LOG_PATH 'hwid'
    formatline $LOG_PATH 'imei'
    formatline $LOG_PATH 'imsi'
    formatline $LOG_PATH 'name'
    formatline $LOG_PATH 'phone'
    formatline $LOG_PATH 'routermac'
    formatline $LOG_PATH 'routerssid'
    formatline $LOG_PATH 'simid'
    formatline $LOG_PATH 'testerName'
    formatline $LOG_PATH 'wifimac'
}

if [ $# -eq 1 ]; then
    LOG_FILE=$1
    DEV_FILE=${LOG_FILE%.log}.device
    ID_FILE=${LOG_FILE%.log}.idf

    if [ -f $LOG_FILE ] && [ ! -f $DEV_FILE ]; then
        (>&2 echo "Regenerating $DEV_FILE")
        devfileregen $LOG_FILE > $DEV_FILE
    fi

    if [ -s $DEV_FILE ]; then
        HWID=$(grep 'hwid' $DEV_FILE | cut -d ' ' -f2)
        $SAWDUST_SCRIPT $LOG_FILE $DEV_FILE $HWID id_search > $ID_FILE || true
        python2 $ID_SEARCH_SCRIPT $ID_FILE || true
    else
        (>&2 echo "Empty device file $DEV_FILE")
    fi
fi
