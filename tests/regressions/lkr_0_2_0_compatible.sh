#!/bin/bash
echo -e "show_keys k, f, p specified:\n"
locker -show_keys --k tests/donotuse.pem --f tests/test.lkr_0_2_0 --p password | grep this_is_a_key