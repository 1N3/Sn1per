if [ "$SSL" = "true" ]; then
	AUTHOR='@xer0dayz'
	VULN_NAME='Insecure SSL TLS Connection CN Mismatch'
	FILENAME="$LOOT_DIR/web/curldebug-$TARGET.txt"
	MATCH='failed to verify the legitimacy of the server'
	SEVERITY='P3 - MEDIUM'
	GREP_OPTIONS='-i'
	SEARCH='positive'
	SECONDARY_COMMANDS=''
	URI="/"
else
	break
fi
