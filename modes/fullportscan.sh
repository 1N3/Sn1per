if [ "$FULLNMAPSCAN" = "0" ]; then
  echo -e "${OKGREEN}====================================================================================${RESET}"
  echo -e "$OKRED SKIPPING FULL NMAP PORT SCAN $RESET"
  echo -e "${OKGREEN}====================================================================================${RESET}"
else
  echo -e "${OKGREEN}====================================================================================${RESET}"
  echo -e "$OKRED RUNNING FULL PORT SCAN $RESET"
  echo -e "${OKGREEN}====================================================================================${RESET}"
  #nmap -Pn -A -v -T4 -p$DEFAULT_TCP_PORTS $TARGET -oX $LOOT_DIR/nmap/nmap-$TARGET.xml | tee $LOOT_DIR/nmap/nmap-$TARGET.txt
  nmap -vv -sT -sV -O -A -T4 -oX $LOOT_DIR/nmap/nmap-$TARGET-fullport.xml -p $FULL_PORTSCAN_PORTS $TARGET | tee $LOOT_DIR/nmap/nmap-$TARGET
  cp -f $LOOT_DIR/nmap/nmap-$TARGET-fullport.xml $LOOT_DIR/nmap/nmap-$TARGET.xml 2> /dev/null
  sed -r "s/</\&lh\;/g" $LOOT_DIR/nmap/nmap-$TARGET 2> /dev/null > $LOOT_DIR/nmap/nmap-$TARGET.txt 2> /dev/null
  rm -f $LOOT_DIR/nmap/nmap-$TARGET 2> /dev/null
  xsltproc $INSTALL_DIR/bin/nmap-bootstrap.xsl $LOOT_DIR/nmap/nmap-$TARGET.xml -o $LOOT_DIR/nmap/nmapreport-$TARGET.html 2> /dev/null
  echo -e "${OKGREEN}====================================================================================${RESET}"
  echo -e "$OKRED PERFORMING UDP PORT SCAN $RESET"
  echo -e "${OKGREEN}====================================================================================${RESET}"
  nmap -Pn -sU -sV -A -T4 -v -p $DEFAULT_UDP_PORTS $TARGET -oX $LOOT_DIR/nmap/nmap-$TARGET-fullport-udp.xml | tee $LOOT_DIR/nmap/nmap-$TARGET-udp
  sed -r "s/</\&lh\;/g" $LOOT_DIR/nmap/nmap-$TARGET-udp 2> /dev/null > $LOOT_DIR/nmap/nmap-$TARGET-udp.txt 2> /dev/null
  rm -f $LOOT_DIR/nmap/nmap-$TARGET 2> /dev/null
fi