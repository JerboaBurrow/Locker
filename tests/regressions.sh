#!/bin/bash

EXIT=1

while [[ $# -gt 0 ]]; do
  case $1 in
    -e|--exit)
      EXIT=0
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


repeat(){
	for i in {1..80}; do echo -n "$1"; done
}

STATUS=0
for reg in $(ls tests/regressions); 
do 
    repeat - && echo
    source tests/regressions/$reg
    if [ $? -ne 0 ];
    then 
        STATUS=1
        echo "FAILED"
    else
        echo "PASSED"
    fi
done

repeat - && echo

if [ $STATUS -eq 0 ];
then 
    echo "PASSED"
else 
    echo "FAILED"
fi

if [ $EXIT -eq 0 ];
then 
    exit $STATUS
fi