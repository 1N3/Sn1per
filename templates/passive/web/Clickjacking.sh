if [ -f $LOOT_DIR/web/headers-http-$TARGET.txt ]; then
	if [ "$SSL" = "false" ]; then
		AUTHOR='@xer0dayz'
		VULN_NAME='Clickjacking HTTP'
		FILENAME="$LOOT_DIR/web/headers-http-$TARGET.txt"
		MATCH="x-frame-options"
		SEVERITY='P4 - LOW'
		GREP_OPTIONS='-i'
		SEARCH='negative'
		SECONDARY_COMMANDS=''
		URI=""
	else
		AUTHOR='@xer0dayz'
		VULN_NAME='Clickjacking HTTPS'
		FILENAME="$LOOT_DIR/web/headers-https-$TARGET.txt"
		MATCH="x-frame-options"
		SEVERITY='P4 - LOW'
		GREP_OPTIONS='-i'
		SEARCH='negative'
		SECONDARY_COMMANDS=''
		URI=""
	fi
fi