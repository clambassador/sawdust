if [ $# -le 0 ];
then
	echo "script usage: sh run-id.sh path"
	exit 0
fi

for i in $(find $1 -iname  '*.log')
do
	echo $i >&2
	dev=${i%.log}.device
	if [ -e $dev ];
	then
		hwid=$(cat $dev | grep hwid | cut -d ' ' -f2)
		./sawdust $i $dev $hwid id_search > /tmp/id_search.csv
		python id_search.py /tmp/id_search.csv
		if [ $? -ne 0 ];
		then
			echo "script usage: sh run.sh processor args"
			exit $?
		fi
	fi

done;
