echo -e "show_keys p specified, correct dir:\n"
(cd tests; locker show_keys -p password | grep -e "this_is_a_key")
