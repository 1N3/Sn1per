AUTHOR='@xer0dayz'
VULN_NAME='SolarWinds Orion Default Credentials 2'
URI=':17778/SolarWinds/InformationService/v3/Json/Query?query=SELECT+Uri+FROM+Orion.Pollers+ORDER+BY+PollerID+WITH+ROWS+1+TO+3+WITH+TOTALROW'
METHOD='GET'
MATCH="totalRow"
SEVERITY='P2 - HIGH'
CURL_OPTS="--user-agent '' -s -L --insecure -H 'Authorization: Basic YWRtaW46' -H 'Content-Type: application/json' "
SECONDARY_COMMANDS=''
GREP_OPTIONS=''