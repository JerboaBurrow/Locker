#!/bin/bash
COLOUR=1

while [[ $# -gt 0 ]]; do
  case $1 in
    -c|--colour)
      COLOUR=0
      shift # past argument
      ;;
    -*|--*)
      echo "Unknown option $1"
      exit 1
      ;;
    *)
      POSITIONAL_ARGS+=("$1") # save positional arg
      shift # past argument
      ;;
  esac
done

if [ $COLOUR -eq 0 ];
then
  RED='\033[0;31m'
  GREEN='\033[0;32m'
  NC='\033[0m'
else
  RED=''
  GREEN=''
  NC='' 
fi

for f in insert retrieve t.lkr t.lkr.bk; do
	if [ -f $f ]; then
		rm $f
	fi
done

touch insert retrieve
for key in {1..1024}; do
	tic=$(date +%s%N | cut -b1-13)
	locker $key $(($RANDOM % 10)) --k tests/donotuse.pem --p password --f t.lkr
	toc=$(date +%s%N | cut -b1-13)
	millis=$((toc-tic))
	echo "$key, $millis" >> insert

        tic=$(date +%s%N | cut -b1-13)
	locker $key --k tests/donotuse.pem --p password --f t.lkr > /dev/null
	toc=$(date +%s%N | cut -b1-13)
        millis=$((toc-tic))
        echo "$key, $millis" >> retrieve

done

echo "${GREEN}.lkr size for 1024 keys: $(du -sh t.lkr)${NC}"

gnuplot -e 'set term dumb 59 26; set xlabel "Number of keys"; set ylabel "Milliseconds"; plot "insert" title "Insert, milliseconds" pt "*";'

gnuplot -e 'set term dumb 59 26; set xlabel "Number of keys"; set ylabel "Milliseconds"; plot "retrieve" title "Retrieve, milliseconds" pt "*";'

