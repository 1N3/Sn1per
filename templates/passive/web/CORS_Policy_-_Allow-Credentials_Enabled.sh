AUTHOR='@xer0dayz'
VULN_NAME='CORS Policy - Allow-Credentials Enabled'
FILENAME="$LOOT_DIR/web/headers-htt*-$TARGET.txt"
MATCH='Access-Control-Allow-Credentials: true'
SEVERITY='P4 - LOW'
GREP_OPTIONS='-i'
SEARCH='positive'
SECONDARY_COMMANDS=''