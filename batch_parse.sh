if [ "$#" -ne 1 ];
then
	echo "usage: sh batch_parse.sh file_of_words"
	exit
fi

while read -r line;
do
	grep -i -a $line keymap.csv
done < $1
