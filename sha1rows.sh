if [ "$#" -ne 1 ];
then
	echo "usage: sh sha1rows.sh file_of_search_args"
	exit
fi

rm $1_sha1
while read -r line;
do
	echo -n $line | sha1sum | cut -d' ' -f1 >> $1_sha1
done < $1

