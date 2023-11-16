echo -e "show_keys p specified, wrong dir:\n"
locker show_keys -p password | grep -e "No match"
