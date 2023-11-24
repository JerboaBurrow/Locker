#!/bin/bash
echo -e "retrieve existing key k, f, p specified:\n"
locker this_is_a_key --k tests/donotuse.pem --f tests/test.lkr --p password | grep this_is_a_secret_value
