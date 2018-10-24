if [ "$OSINT" = "1" ]; then
	echo -e "${OKGREEN}====================================================================================${RESET}"
	echo -e "$OKRED GATHERING OSINT INFO $RESET"
	echo -e "${OKGREEN}====================================================================================${RESET}"
	python2.7 $THEHARVESTER -d $TARGET -l 100 -b all 2> /dev/null | tee $LOOT_DIR/osint/theharvester-$TARGET.txt
	metagoofil -d $TARGET -t doc,pdf,xls,csv,txt -l 25 -n 25 -o $LOOT_DIR/osint/ -f $LOOT_DIR/osint/$TARGET.html 2> /dev/null | tee $LOOT_DIR/osint/metagoofil-$TARGET.txt
fi