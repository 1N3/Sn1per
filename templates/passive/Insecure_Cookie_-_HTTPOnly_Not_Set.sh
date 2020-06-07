AUTHOR='@xer0dayz'
VULN_NAME='Insecure Cookie - HTTPOnly Not Set'
FILENAME="$LOOT_DIR/web/headers-htt*-$TARGET.txt"
MATCH='Set-Cookie'
SEVERITY='P3 - MEDIUM'
GREP_OPTIONS='-i'
SEARCH='positive'
SECONDARY_COMMANDS=' | egrep -iv httponly'