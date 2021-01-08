AUTHOR='@xer0dayz'
VULN_NAME='Fortinet FortiGate SSL VPN Panel Detected 1'
URI='/remote/login?lang=en'
METHOD='GET'
MATCH="launchFortiClient"
SEVERITY='P5 - INFO'
CURL_OPTS="--user-agent '' -s -L --insecure"
SECONDARY_COMMANDS=''
GREP_OPTIONS='-i'