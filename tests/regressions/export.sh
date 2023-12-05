#!/bin/bash
echo -e "export k, f, p specified:\n"
locker --export data --k tests/donotuse.pem --f tests/test.lkr --p password
cat data | grep "this_is_a_secret_value"