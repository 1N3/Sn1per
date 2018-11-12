if [ "$FULLNMAPSCAN" = "0" ]; then
  echo -e "${OKGREEN}====================================================================================${RESET}"
  echo -e "$OKRED SKIPPING FULL NMAP PORT SCAN $RESET"
  echo -e "${OKGREEN}====================================================================================${RESET}"
else
  echo -e "${OKGREEN}====================================================================================${RESET}"
  echo -e "$OKRED RUNNING FULL PORT SCAN $RESET"
  echo -e "${OKGREEN}====================================================================================${RESET}"
  #nmap -Pn -A -v -T4 -p$DEFAULT_TCP_PORTS $TARGET -oX $LOOT_DIR/nmap/nmap-$TARGET.xml | tee $LOOT_DIR/nmap/nmap-$TARGET.txt
  nmap -vv -sT -O -A -T4 -oX $LOOT_DIR/nmap/nmap-$TARGET.xml $TARGET | tee $LOOT_DIR/nmap/nmap-$TARGET.txt
  xsltproc $INSTALL_DIR/bin/nmap-bootstrap.xsl $LOOT_DIR/nmap/nmap-$TARGET.xml -o $LOOT_DIR/nmap/nmapreport-$TARGET.html 2> /dev/null
  echo -e "${OKGREEN}====================================================================================${RESET}"
  echo -e "$OKRED PERFORMING UDP PORT SCAN $RESET"
  echo -e "${OKGREEN}====================================================================================${RESET}"
  nmap -Pn -sU -A -T4 -v -p$DEFAULT_UDP_PORTS $TARGET -oX $LOOT_DIR/nmap/nmap-$TARGET-udp.xml
fi