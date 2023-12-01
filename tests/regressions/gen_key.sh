#!/bin/bash
echo -e "show_keys k, f, p specified:\n"
locker --gen_key gen_key.pem --p password
locker this_is_a_key this_is_a_secret_value --f gen.lkr --k gen_key.pem --p password
locker -show_keys --f gen.lkr --k gen_key.pem --p password | grep this_is_a_key

rm gen_key.pem gen.lkr