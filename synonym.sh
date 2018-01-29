if [ "$#" -ne 1 ];
then
	echo "usage: sh synonym.sh file_of_search_args"
	exit
fi

rm /tmp/hits
while read -r line;
do
	grep -i -a $line keymap.csv | cut -d, -f8 >> /tmp/hits
done < $1

python table.py /tmp/hits | sort -n
