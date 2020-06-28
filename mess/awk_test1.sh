#!/bin/bash
while IFS= read -r line;
do
	echo "line:$line"
	[[ $line = *Rank* ]] || continue
	read -r _ _ _ rank _ <<<"$line"
	echo $rank
	case $rank in
		1-Strong) mv -- awk1.txt ~/test/1/ ;;
	esac
done < awk1.txt
