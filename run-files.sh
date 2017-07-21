if [ $# -le 0 ];
then
	echo "script usage: sh run.sh path"
	exit 0
fi
for i in $(find $1 -iname  '*.log')
do
	echo $i >&2
	dev=${i%.log}.device
	ret=$(sh get-files-read.sh $i | sort | uniq)
	echo "${ret}"
done;
