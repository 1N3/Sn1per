AUTHOR='@xer0dayz'
VULN_NAME='X-Powered-By Header Found'
FILENAME="$LOOT_DIR/web/headers-htt*-$TARGET.txt"
MATCH='X-Powered-By'
SEVERITY='P5 - INFO'
GREP_OPTIONS='-i'
SEARCH='positive'
SECONDARY_COMMANDS=''