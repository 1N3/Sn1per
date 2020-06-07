AUTHOR='@xer0dayz'
VULN_NAME='Weak Authentication'
URI='/'
METHOD='GET'
MATCH='realm\='
SEVERITY='P4 - LOW'
CURL_OPTS="-I -L --user-agent '' -s --insecure"
SECONDARY_COMMANDS=''
GREP_OPTIONS='-i'

if [[ "$SSL" == "false" ]]; then
	SEVERITY='P2 - HIGH'
fi