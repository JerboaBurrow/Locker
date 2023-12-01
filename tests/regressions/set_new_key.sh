#!/bin/bash
echo -e "set new key k, f, p specified:\n"
cp tests/test.lkr reg.lkr
locker this_is_a_new_key abc -o --k tests/donotuse.pem --f reg.lkr --p password
locker this_is_a_new_key --k tests/donotuse.pem --f reg.lkr --p password | grep "abc"

rm reg.lkr reg.lkr.bk