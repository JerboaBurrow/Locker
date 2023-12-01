#!/bin/bash
echo -e "set existing key k, f, p specified:\n"
cp tests/test.lkr reg.lkr
locker this_is_a_key abc --k tests/donotuse.pem --f reg.lkr --p password | grep "Key already exists"
locker this_is_a_key --k tests/donotuse.pem --f reg.lkr --p password | grep "this_is_a_secret_value"

rm reg.lkr reg.lkr.bk