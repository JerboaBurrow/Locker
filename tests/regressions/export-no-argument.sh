#!/bin/bash
echo -e "export, no argument, k, f, p specified:\n"
locker --export --k tests/donotuse.pem --f tests/test.lkr --p password
cat exported | grep "this_is_a_secret_value"