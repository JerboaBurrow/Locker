#!/bin/bash
echo -e "show_keys k, f, p specified, -p is wrong:\n"
locker -show_keys --k tests/donotuse.pem --f tests/test.lkr --p wrong_password | grep "Incorrect password"
