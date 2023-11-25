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
  NC='\033[0m'
else
  C=''
  NC='' 
fi

repeat(){
	for i in {1..80}; do echo -n "$1"; done
}

for target in $(ls fuzz/fuzz_targets/); do
	repeat - && echo
	name=$(echo "$target" | cut -f 1 -d '.')
	echo -e "${C}Fuzzing: $name${NC}, for $TIMEOUT seconds"
	cargo fuzz run $name -- -max_total_time=$TIMEOUT
done

repeat - && echo

echo -e "${C}Fuzzing complete${NC}"