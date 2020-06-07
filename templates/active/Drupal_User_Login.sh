AUTHOR='@xer0dayz'
VULN_NAME='Drupal User Login'
URI='/user/login?destination=/'
METHOD='GET'
MATCH='user-login-form'
SEVERITY='P5 - INFO'
CURL_OPTS="--user-agent '' -s -L --insecure"
SECONDARY_COMMANDS=''
GREP_OPTIONS='-i'