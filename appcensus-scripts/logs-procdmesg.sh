#!/bin/bash

DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
source $DIR/common-local.sh

if [ $# -eq 1 ]; then
    LOG_FILE=$1
    DMESG="${LOG_FILE%%.log}.dmesg"

    if [ -f $DMESG ]; then
        DMESG_FILE=$(basename $DMESG)
        APP=$(echo ${DMESG_FILE%%.dmesg} | cut -d- -f1)
        VCODE=$(echo ${DMESG_FILE%%.dmesg} | cut -d- -f2)

        TEST_TIME=$(echo ${DMESG_FILE%%.dmesg} | cut -d- -f4)
        TEST_YEAR=${TEST_TIME:0:4}
        TEST_MONTH=${TEST_TIME:4:2}
        TEST_DAY=${TEST_TIME:6:2}
        TEST_HOUR=${TEST_TIME:8:2}
        TEST_MIN=${TEST_TIME:10:2}
        TEST_SEC=${TEST_TIME:12:2}
        TIMESTAMP=$(date -d "$TEST_YEAR-$TEST_MONTH-$TEST_DAY $TEST_HOUR:$TEST_MIN:$TEST_SEC UTC" +%s)

        # Find the app's PID
        APP_PID=$(egrep "/data/app/$APP.*odex$" $DMESG | sed "s/^.*UCB-FS:/UCB-FS:/" | xargs | awk '{print $3}')

        # Find "UCB-FS: OPEN" lines that belong to the app's PID
        # then eliminate duplicates while otherwise preserving the original order
        egrep "UCB-FS: OPEN $APP_PID $APP_PID" $DMESG | \
        sed "s/^.*UCB-FS:/UCB-FS:/" | \
        awk -v OFS=',' -v app=$APP -v vcode=$VCODE -v timestamp=$TIMESTAMP '{print app,vcode,timestamp,$5,substr($0,index($0,$7))}' | \
        cat -n | sort -uk2 | sort -nk1 | cut -f2-
    else
        (>&2 echo "No dmesg file $DMESG")
    fi
fi
