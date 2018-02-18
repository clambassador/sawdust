grep "PermissionDeciderManager-UCB: Packages list: " $1 | while read -r line ; do
	TEE=`echo $line | cut -d'-' -f3 | cut -d' ' -f4`
#echo $line >&2
	echo $TEE >&2
	ID=`echo $TEE | cut -d: -f1`
	APP=`echo $TEE | cut -d: -f2`
	if [ -z "$ID" ]; then
		if [ -z "$APP" ]; then
			echo $1 $APP
			if [[ $(grep -m 1 $APP $1) ]]; then
				echo "HI"
				echo `grep " DataRecorder: $ID SQL" $1 | cut -c12-`
				grep " DataRecorder: $ID SQL" $1 | cut -d' ' -f10- | while read -r l ; do
					echo $ID,$APP,$l
				done
				else
					echo "BYE"
			fi;
			echo "TOT"
		fi;
	fi;
done
