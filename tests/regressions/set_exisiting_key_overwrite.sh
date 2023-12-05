#!/bin/bash
echo -e "set existing key k, f, p, o specified:\n"
cp tests/test.lkr reg.lkr
locker this_is_a_key abc -o --k tests/donotuse.pem --f reg.lkr --p password
locker this_is_a_key --k tests/donotuse.pem --f reg.lkr --p password | grep "abc"