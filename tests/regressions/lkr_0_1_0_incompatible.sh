#!/bin/bash
echo -e "incompatible locker file (0.1.0) show_keys k, f, p specified:\n"
locker -show_keys --k tests/donotuse.pem --f tests/test.lkr_0_1_0 --p password | grep "Incompatible lkr file"
