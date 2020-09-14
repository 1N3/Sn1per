if [ "$SSL" = "false" ]; then
	AUTHOR='@xer0dayz'
	VULN_NAME='Clear-Text Protocol - HTTP'
	FILENAME="$LOOT_DIR/web/headers-http-$TARGET.txt"
	MATCH="200\ OK"
	SEVERITY='P2 - HIGH'
	GREP_OPTIONS='-i'
	SEARCH='positive'
	SECONDARY_COMMANDS=''
else
	break
fi