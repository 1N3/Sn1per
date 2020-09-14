if [ "$SSL" = "true" ]; then
	AUTHOR='@xer0dayz'
	VULN_NAME='Weak SSL TLS Protocols'
	FILENAME="$LOOT_DIR/web/sslscan-$TARGET.txt"
	MATCH=' SSLv'
	SEVERITY='P2 - HIGH'
	GREP_OPTIONS='-i'
	SEARCH='positive'
	SECONDARY_COMMANDS=''
fi