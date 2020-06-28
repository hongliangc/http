#!/bin/bash
IP=1.2.3.4
IFS="."
TEMPIP=$(echo $IP)
IFS=" "
echo $TEMPIP
for x in $TEMPIP;
do
	Xip="$x.$Xip"
	echo "Xip:"$Xip
done
echo ${Xip%.}

