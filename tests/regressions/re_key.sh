#!/bin/bash
echo -e "re_key:\n"
cp tests/test.lkr reg.lkr
locker --re_key gen_key.pem new_password --p password --k tests/donotuse.pem
locker -show_keys --k gen_key.pem --p new_password --f reg.lkr | grep this_is_a_key