i=$1

if [ -z $i ]
then
	return;
fi
if [ ! -e $i ]
then
	return;
fi

dev=${i%.log}.device
app=$(grep "Installing" $i | cut -d' ' -f5)
uid=0
last=0
for line in $(grep "OPEN" $i | grep $app)

do
	number=$(expr $line)
	if [ $number -eq $last ] 2>/dev/null;
	then
		if [ $number -ge 10065 ];
		then
			uid=$last
			break
		fi
	fi

	last=$number
done;

if [ $uid -ne 0 ];
then
	echo $uid
fi

x=$(grep "OPEN $uid" $i | cut -d' ' -f10)
echo "${x}"
