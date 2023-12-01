#!/bin/bash

EXIT=1
COLOUR=1

while [[ $# -gt 0 ]]; do
  case $1 in
    -e|--exit)
      EXIT=0
      shift # past argument
      ;;
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

repeat(){
	for i in {1..80}; do echo -n "$1"; done
}

declare -a FAILING

STATUS=0
for reg in $(ls tests/regressions); 
do 
    repeat - && echo
    echo -e "regression: $reg\n\n" 
    source tests/regressions/$reg
    if [ $? -ne 0 ];
    then 
        STATUS=1
        echo -e "\n${RED}FAILED${NC}"
        FAILING+=("'$reg'")
    else
        echo -e "\n${GREEN}PASSED${NC}"
    fi

    for f in reg.* *.pem *.lkr; do 
      if [ -f $f ]; then
        rm $f
      fi
    done
done

repeat - && echo

if [ $STATUS -eq 0 ];
then 
    echo -e "${GREEN}PASSED${NC}"
else 
    echo -e "${RED}FAILED${NC}"
    echo -e "${RED}FAILING: ${FAILING[*]}"
fi

if [ $EXIT -eq 0 ];
then 
    exit $STATUS
fi