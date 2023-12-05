#!/bin/bash
echo -e "delete key k, f, p specified:\n"
cp tests/test.lkr reg.lkr
locker this_is_a_key -d --k tests/donotuse.pem --f reg.lkr --p password
locker this_is_a_key --k tests/donotuse.pem --f reg.lkr --p password | grep "Key does not exist"

