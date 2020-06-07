AUTHOR='@xer0dayz'
VULN_NAME='Clickjacking'
FILENAME="$LOOT_DIR/web/headers-htt*-$TARGET.txt"
MATCH='X-Frame-Options'
SEVERITY='P4 - LOW'
GREP_OPTIONS='-i'
SEARCH="negative"
SECONDARY_COMMANDS=''