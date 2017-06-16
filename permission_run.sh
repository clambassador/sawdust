if [ $# -le 0 ];
then
	echo "script usage: sh permission_run.sh path"
	exit 0
fi

for i in $(find $1 -iname  '*.log')
do
	echo $i >&2
	./permission_processor $i
done;
