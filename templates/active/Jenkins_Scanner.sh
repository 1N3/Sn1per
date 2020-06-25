AUTHOR='@xer0dayz'
VULN_NAME='Jenkins Detected'
URI='/login?from=%2F'
METHOD='GET'
MATCH="\[Jenkins\]"
SEVERITY='P5 - INFO'
CURL_OPTS="--user-agent '' -s -L --insecure"
SECONDARY_COMMANDS=''
GREP_OPTIONS='-i'