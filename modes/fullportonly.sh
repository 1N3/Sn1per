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
    nmap -Pn -A -v -T4 -p$DEFAULT_TCP_PORTS $TARGET -oX $LOOT_DIR/nmap/nmap-$TARGET.xml | tee $LOOT_DIR/nmap/nmap-$TARGET.txt
    xsltproc $INSTALL_DIR/bin/nmap-bootstrap.xsl $LOOT_DIR/nmap/nmap-$TARGET.xml -o $LOOT_DIR/nmap/nmapreport-$TARGET.html 2> /dev/null
    echo -e "${OKGREEN}====================================================================================${RESET}"
    echo -e "$OKRED PERFORMING UDP PORT SCAN $RESET"
    echo -e "${OKGREEN}====================================================================================${RESET}"
    nmap -Pn -sU -A -T4 -v -p$DEFAULT_UDP_PORTS $TARGET -oX $LOOT_DIR/nmap/nmap-$TARGET-udp.xml
  else
    echo -e "${OKGREEN}====================================================================================${RESET}"
    echo -e "$OKRED PERFORMING TCP PORT SCAN $RESET"
    echo -e "${OKGREEN}====================================================================================${RESET}"
    nmap -Pn -A -v -T4 -p $PORT $TARGET -oX $LOOT_DIR/nmap/nmap-$TARGET.xml | tee $LOOT_DIR/nmap/nmap-$TARGET.txt
    xsltproc $INSTALL_DIR/bin/nmap-bootstrap.xsl $LOOT_DIR/nmap/nmap-$TARGET.xml -o $LOOT_DIR/nmap/nmapreport-$TARGET.html 2> /dev/null
    echo -e "${OKGREEN}====================================================================================${RESET}"
    echo -e "$OKRED PERFORMING UDP PORT SCAN $RESET"
    echo -e "${OKGREEN}====================================================================================${RESET}"
    nmap -Pn -A -v -T4 -sU -p $PORT -Pn $TARGET -oX $LOOT_DIR/nmap/nmap-$TARGET.xml >> $LOOT_DIR/nmap/nmap-$TARGET.txt
  fi
  echo -e "${OKGREEN}====================================================================================${RESET}"
  echo -e "$OKRED DONE $RESET"
  echo -e "${OKGREEN}====================================================================================${RESET}"
  loot
  exit
fi

if [ "$MODE" = "port" ]; then
  if [ -z "$PORT" ]; then
    echo -e "$OKRED + -- --=[Error: You need to enter a port number. $RESET"
    exit
  fi
fi
