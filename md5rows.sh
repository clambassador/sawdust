if [ "$#" -ne 1 ];
then
	echo "usage: sh md5rows.sh file_of_search_args"
	exit
fi

rm $1_md5
while read -r line;
do
	echo -n $line | md5sum | cut -d' ' -f1 >> $1_md5
done < $1

