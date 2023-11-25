#!/bin/bash

COLOUR=1
TIMEOUT=10
while [[ $# -gt 0 ]]; do
  case $1 in
    -c|--colour)
      COLOUR=0
      shift
      ;;
	-t|--timeout)
	  TIMEOUT=$2
	  shift
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
  C='\033[096m'
  G='\033[0;32m'
  NC='\033[0m'
else
  C=''
  NC='' 
fi

repeat(){
	for i in {1..80}; do echo -n "$1"; done
}

echo -e "${C}Found fuzz targets:${NC}"
for target in $(ls fuzz/fuzz_targets/); do
  echo -en "  ${C}$target${NC}"
done
echo ""

count=$(ls fuzz/fuzz_targets/ | wc -l)
current=1

for target in $(ls fuzz/fuzz_targets/); do
	repeat - && echo
	name=$(echo "$target" | cut -f 1 -d '.')
echo -e "${C}Fuzzing: $name, for $TIMEOUT seconds, ${NC}${G}$current/$count${NC}"
	cargo fuzz run $name -- -max_total_time=$TIMEOUT
  current=$(($current+1))
done

repeat - && echo

echo -e "${C}Fuzzing complete${NC}"