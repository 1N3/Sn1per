AUTHOR='@xer0dayz'
VULN_NAME='Drupal Version Disclosure'
URI='/core/install.php?profile=default'
METHOD='GET'
MATCH='site-version'
SEVERITY='P4 - LOW'
CURL_OPTS="--user-agent '' -s -L --insecure"
SECONDARY_COMMANDS=''
GREP_OPTIONS='-i'