if [ -f $LOOT_DIR/web/headers-http-$TARGET.txt ]; then
	if [ "$SSL" = "true" ]; then
		AUTHOR='@xer0dayz'
		VULN_NAME='CSP Not Enforced'
		FILENAME="$LOOT_DIR/web/headers-https-$TARGET.txt"
		MATCH="content-security-policy"
		SEVERITY='P5 - INFO'
		GREP_OPTIONS='-i'
		SEARCH='negative'
		SECONDARY_COMMANDS=''
		URI=""
	else
		AUTHOR='@xer0dayz'
		VULN_NAME='CSP Not Enforced'
		FILENAME="$LOOT_DIR/web/headers-http-$TARGET.txt"
		MATCH="content-security-policy"
		SEVERITY='P5 - INFO'
		GREP_OPTIONS='-i'
		SEARCH='negative'
		SECONDARY_COMMANDS=''
		URI=""
	fi
fi