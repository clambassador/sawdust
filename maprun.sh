if [ $# -le 2 ];
then
	echo "sh maprun.sh file col command"
	exit 0
fi

RANGE=`cut -d, -f $2 $1 | sort | uniq`
for i in $RANGE; do
	if [ $2 -eq 1 ];
	then
		echo $i `grep "^$i," $1 | $3`
	else
		echo $i `grep ",$i," $1 | $3`
	fi
		
done;
