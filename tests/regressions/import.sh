#!/bin/bash
echo -e "import into new lkr, k, f, p specified:\n"
locker --import tests/import --k tests/donotuse.pem --f reg.lkr --p password
locker this_is_an_imported_key --f reg.lkr --k tests/donotuse.pem --p password | grep "this_is_an_imported_secret_value"