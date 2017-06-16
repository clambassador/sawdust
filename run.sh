if [ $# -le 1 ];
then
	echo "script usage: sh run.sh path processor args"
	exit 0
fi
for i in $(find $1 -iname  '*.log')
do
	echo $i >&2
	dev=${i%.log}.device
	if [ -e $dev ];
	then
		hwid=$(cat $dev | grep hwid | cut -d ' ' -f2)
		./sawdust $i $dev $hwid $2 $3 $4 $5 $6 $7 $8
		if [ $? -ne 0 ];
		then
			echo "script usage: sh run.sh processor args"
			exit $?
		fi
	fi

done;
