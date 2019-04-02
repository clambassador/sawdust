#!/bin/bash

DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
source $DIR/common-local.sh

if [ $# -eq 1 ]; then
    LOG_FILE=$1
    if [ -f $LOG_FILE ]; then
        BASE_FILE=$(basename $LOG_FILE)
        APP=$(echo ${BASE_FILE%%.log} | cut -d- -f1)
        VCODE=$(echo ${BASE_FILE%%.log} | cut -d- -f2)

        TEST_TIME=$(echo ${BASE_FILE%%.log} | cut -d- -f4)
        TEST_YEAR=${TEST_TIME:0:4}
        TEST_MONTH=${TEST_TIME:4:2}
        TEST_DAY=${TEST_TIME:6:2}
        TEST_HOUR=${TEST_TIME:8:2}
        TEST_MIN=${TEST_TIME:10:2}
        TEST_SEC=${TEST_TIME:12:2}
        TIMESTAMP=$(date -d "$TEST_YEAR-$TEST_MONTH-$TEST_DAY $TEST_HOUR:$TEST_MIN:$TEST_SEC UTC" +%s || echo '0')

        # Get the app's PID
        PID=$(grep "PermissionDeciderManager-UCB: Packages list: .*$APP " $LOG_FILE | head -n1 | awk -F ':' '{print $5}' | xargs)
        PID_SEARCH=$PID

        # Get additional PIDs from spawned processes
        while read -r EXTRA_PID; do
            PID_SEARCH="$PID_SEARCH|$EXTRA_PID"
        done < <(grep "I ActivityManager: Start proc [[:digit:]]\+:$APP" $LOG_FILE | sed 's/^.*I ActivityManager: Start proc //' | cut -d ':' -f1 )

        # Get exec calls from this PID
        grep "I System.out: SensitiveRequest:execCommand:" $LOG_FILE | egrep "$PID_SEARCH  [[:digit:]]" | \
        sed 's/^.*I System.out: SensitiveRequest:execCommand://' | \
        sed 's/:null$//' | \
        awk -v OFS=',' -v app=$APP -v vcode=$VCODE -v timestamp=$TIMESTAMP '{n=split($1,A,"/"); print app,vcode,timestamp,A[n],$0}'
    else
        (>&2 echo "No log file $LOG_FILE")
    fi
fi
