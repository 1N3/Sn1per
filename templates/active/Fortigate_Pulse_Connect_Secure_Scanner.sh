AUTHOR='@xer0dayz'
VULN_NAME='Fortigate Pulse Connect Secure Detected'
URI='/remote/login?lang=en'
METHOD='GET'
MATCH="<title>Please Login</title>"
SEVERITY='P5 - INFO'
CURL_OPTS="--user-agent '' -s -L --insecure"
SECONDARY_COMMANDS=''
GREP_OPTIONS='-i'