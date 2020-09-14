AUTHOR='@xer0dayz'
VULN_NAME='RabbitMQ Management Default Credentials'
URI="/api/whoami"
METHOD='GET'
MATCH="{\"name\":\"guest\""
SEVERITY='P2 - HIGH'
CURL_OPTS='-H "Content-Type: application/json" -H "Authorization: Z3Vlc3Q6Z3Vlc3Q=" --user-agent '' -s -L --insecure'
SECONDARY_COMMANDS=''
GREP_OPTIONS='-i'