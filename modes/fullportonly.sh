# FULLPORTONLY MODE
if [ "$MODE" = "fullportonly" ]; then

  if [ "$REPORT" = "1" ]; then
    args="-t $TARGET"
    if [ ! -z "$WORKSPACE" ]; then
      args="$args -w $WORKSPACE"
      LOOT_DIR=$INSTALL_DIR/loot/workspace/$WORKSPACE
      echo -e "$OKBLUE[*] Saving loot to $LOOT_DIR [$RESET${OKGREEN}OK${RESET}$OKBLUE]$RESET"
      mkdir -p $LOOT_DIR 2> /dev/null
      mkdir $LOOT_DIR/domains 2> /dev/null
      mkdir $LOOT_DIR/screenshots 2> /dev/null
      mkdir $LOOT_DIR/nmap 2> /dev/null
      mkdir $LOOT_DIR/notes 2> /dev/null
      mkdir $LOOT_DIR/reports 2> /dev/null
      mkdir $LOOT_DIR/scans 2> /dev/null
      mkdir $LOOT_DIR/output 2> /dev/null
    fi
    args="$args --noreport -m fullportonly" 
    echo "sniper -t $TARGET -m $MODE --noreport $args" >> $LOOT_DIR/scans/$TARGET-fullnmapscan.txt
    sniper $args | tee $LOOT_DIR/output/sniper-$TARGET-$MODE-`date +%Y%m%d%H%M`.txt 2>&1
    exit
  fi

  logo
  echo "$TARGET" >> $LOOT_DIR/domains/targets.txt
  if [ -z "$PORT" ]; then
    nmap -vv -sT -sV -O -A -T4 -oX $LOOT_DIR/nmap/nmap-$TARGET-fullport.xml -p $FULL_PORTSCAN_PORTS $TARGET | tee $LOOT_DIR/nmap/nmap-$TARGET
    cp -f $LOOT_DIR/nmap/nmap-$TARGET-fullport.xml $LOOT_DIR/nmap/nmap-$TARGET.xml 2> /dev/null
    sed -r "s/</\&lh\;/g" $LOOT_DIR/nmap/nmap-$TARGET 2> /dev/null > $LOOT_DIR/nmap/nmap-$TARGET.txt 2> /dev/null
    rm -f $LOOT_DIR/nmap/nmap-$TARGET 2> /dev/null
    xsltproc $INSTALL_DIR/bin/nmap-bootstrap.xsl $LOOT_DIR/nmap/nmap-$TARGET.xml -o $LOOT_DIR/nmap/nmapreport-$TARGET.html 2> /dev/null
    echo -e "${OKGREEN}====================================================================================${RESET}"
    echo -e "$OKRED PERFORMING UDP PORT SCAN $RESET"
    echo -e "${OKGREEN}====================================================================================${RESET}"
    nmap -Pn -sU -sV -A -T4 -v -p $DEFAULT_UDP_PORTS $TARGET -oX $LOOT_DIR/nmap/nmap-$TARGET-fullport-udp.xml
    sed -r "s/</\&lh\;/g" $LOOT_DIR/nmap/nmap-$TARGET-udp 2> /dev/null > $LOOT_DIR/nmap/nmap-$TARGET-udp.txt 2> /dev/null
    rm -f $LOOT_DIR/nmap/nmap-$TARGET-udp 2> /dev/null
  else
    echo -e "${OKGREEN}====================================================================================${RESET}"
    echo -e "$OKRED PERFORMING TCP PORT SCAN $RESET"
    echo -e "${OKGREEN}====================================================================================${RESET}"
    nmap -Pn -A -v -sV -T4 -p $PORT $TARGET -oX $LOOT_DIR/nmap/nmap-$TARGET-tcp-port$PORT.xml | tee $LOOT_DIR/nmap/nmap-$TARGET
    sed -r "s/</\&lh\;/g" $LOOT_DIR/nmap/nmap-$TARGET 2> /dev/null > $LOOT_DIR/nmap/nmap-$TARGET.txt 2> /dev/null
    rm -f $LOOT_DIR/nmap/nmap-$TARGET 2> /dev/null
    xsltproc $INSTALL_DIR/bin/nmap-bootstrap.xsl $LOOT_DIR/nmap/nmap-$TARGET.xml -o $LOOT_DIR/nmap/nmapreport-$TARGET.html 2> /dev/null
    echo -e "${OKGREEN}====================================================================================${RESET}"
    echo -e "$OKRED PERFORMING UDP PORT SCAN $RESET"
    echo -e "${OKGREEN}====================================================================================${RESET}"
    nmap -Pn -A -v -sV -T4 -sU -p $PORT -Pn $TARGET -oX $LOOT_DIR/nmap/nmap-$TARGET-udp-port$PORT.xml | tee $LOOT_DIR/nmap/nmap-$TARGET-udp
    sed -r "s/</\&lh\;/g" $LOOT_DIR/nmap/nmap-$TARGET-udp 2> /dev/null > $LOOT_DIR/nmap/nmap-$TARGET-udp.txt 2> /dev/null
    rm -f $LOOT_DIR/nmap/nmap-$TARGET-udp 2> /dev/null
  fi
  echo -e "${OKGREEN}====================================================================================${RESET}"
  echo -e "$OKRED DONE $RESET"
  echo -e "${OKGREEN}====================================================================================${RESET}"
  echo "$TARGET" >> $LOOT_DIR/scans/updated.txt
  loot
  exit
fi

if [ "$MODE" = "port" ]; then
  if [ -z "$PORT" ]; then
    echo -e "$OKRED + -- --=[Error: You need to enter a port number. $RESET"
    exit
  fi
fi
