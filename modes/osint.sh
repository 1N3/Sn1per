if [ "$OSINT" = "1" ]; then
	echo -e "${OKGREEN}====================================================================================${RESET}"
	echo -e "$OKRED GATHERING WHOIS INFO $RESET"
	echo -e "${OKGREEN}====================================================================================${RESET}"
	if [ "$WHOIS" == "1" ]; then
		if [ "$VERBOSE" == "1" ]; then
			echo -e "$OKBLUE[$RESET${OKRED}i${RESET}$OKBLUE]$OKGREEN whois $TARGET 2> /dev/null | tee $LOOT_DIR/osint/whois-$TARGET.txt 2> /dev/null $RESET"
		fi
		whois $TARGET 2> /dev/null | tee $LOOT_DIR/osint/whois-$TARGET.txt 2> /dev/null 
	fi
	echo -e "${OKGREEN}====================================================================================${RESET}"
	echo -e "$OKRED GATHERING OSINT INFO $RESET"
	echo -e "${OKGREEN}====================================================================================${RESET}"
	if [ "$THEHARVESTER" == "1" ]; then
		if [ "$VERBOSE" == "1" ]; then
			echo -e "$OKBLUE[$RESET${OKRED}i${RESET}$OKBLUE]$OKGREEN python2.7 $THEHARVESTER_PATH -d $TARGET -l 100 -b all 2> /dev/null | tee $LOOT_DIR/osint/theharvester-$TARGET.txt 2> /dev/null  $RESET"
		fi
		theharvester -d $TARGET -l 25 -b all 2> /dev/null | tee $LOOT_DIR/osint/theharvester-$TARGET.txt 2> /dev/null 
	fi
	if [ "$METAGOOFIL" == "1" ]; then
		if [ "$VERBOSE" == "1" ]; then
			echo -e "$OKBLUE[$RESET${OKRED}i${RESET}$OKBLUE]$OKGREEN metagoofil -d $TARGET -t doc,pdf,xls,csv,txt -l 25 -n 25 -o $LOOT_DIR/osint/ -f $LOOT_DIR/osint/$TARGET.html 2> /dev/null | tee $LOOT_DIR/osint/metagoofil-$TARGET.txt 2> /dev/null  $RESET"
		fi
		metagoofil -d $TARGET -t doc,pdf,xls,csv,txt -l 25 -n 25 -o $LOOT_DIR/osint/ -f $LOOT_DIR/osint/$TARGET.html 2> /dev/null | tee $LOOT_DIR/osint/metagoofil-$TARGET.txt 2> /dev/null 
	fi
fi
