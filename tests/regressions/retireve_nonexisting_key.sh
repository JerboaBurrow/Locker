#!/bin/bash
echo -e "retrieve non-existing key k, f, p specified:\n"
locker this_is_not_a_key --k tests/donotuse.pem --f tests/test.lkr --p password | grep "Key does not exist"
