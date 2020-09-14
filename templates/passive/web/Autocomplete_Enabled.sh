AUTHOR='@xer0dayz'
VULN_NAME='Autocomplete Enabled'
FILENAME="$LOOT_DIR/web/websource-$TARGET-*.txt"
MATCH='autocomplete=\"on\"'
SEVERITY='P4 - LOW'
GREP_OPTIONS='-i'
SEARCH='positive'
SECONDARY_COMMANDS=''