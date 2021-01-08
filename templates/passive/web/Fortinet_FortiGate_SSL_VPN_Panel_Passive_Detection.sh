AUTHOR='@xer0dayz'
VULN_NAME='Fortinet FortiGate SSL VPN Panel Passive Detection'
FILENAME="$LOOT_DIR/web/headers-htt*-$TARGET.txt"
MATCH="Server\:\ xxxxxxxx-xxxxx"
SEVERITY='P5 - INFO'
GREP_OPTIONS='-i'
SEARCH='positive'
SECONDARY_COMMANDS=''