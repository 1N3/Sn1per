AUTHOR='@xer0dayz'
VULN_NAME='Interesting Domain Found'
echo "$TARGET" > /tmp/target 
FILENAME="/tmp/target"
MATCH="admin|dev|portal|stage|prod|tst|test"
SEVERITY='P5 - INFO'
GREP_OPTIONS='-i'
SEARCH='positive'
SECONDARY_COMMANDS=''
TYPE='network'