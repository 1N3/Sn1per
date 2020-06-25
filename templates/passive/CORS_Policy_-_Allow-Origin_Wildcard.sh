AUTHOR='@xer0dayz'
VULN_NAME='CORS Policy - Allow-Origin Wildcard'
FILENAME="$LOOT_DIR/web/headers-htt*-$TARGET.txt"
MATCH='Access-Control-Allow-Origin: *'
SEVERITY='P4 - LOW'
GREP_OPTIONS='-i'
SEARCH='positive'
SECONDARY_COMMANDS=''