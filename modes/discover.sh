# DISCOVER MODE #####################################################################################################
if [ "$MODE" = "discover" ]; then
  if [ "$REPORT" = "1" ]; then
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
      mkdir $LOOT_DIR/output 2> /dev/null
      mkdir $LOOT_DIR/scans 2> /dev/null
    fi
    OUT_FILE=$(echo "$TARGET" | tr / -)
    echo "sniper -t $TARGET -m $MODE --noreport $args" >> $LOOT_DIR/scans/$OUTFILE-$MODE.txt 2> /dev/null
    sniper -t $TARGET -m $MODE --noreport $args | tee $LOOT_DIR/output/sniper-$MODE-`date +%Y%m%d%H%M`.txt 2>&1
    exit
  fi
  echo -e "$OKRED                                                              ____ /\\"
  echo -e "$OKRED   Sn1per by 1N3 @CrowdShield                                      \ \\"
  echo -e "$OKRED   https://xerosecurity.com                                         \ \\"
  echo -e "$OKRED                                                                ___ /  \\"
  echo -e "$OKRED                                                                    \   \\"
  echo -e "$OKRED                                                                 === > [ \\"
  echo -e "$OKRED                                                                    /   \ \\"
  echo -e "$OKRED                                                                    \   / /"
  echo -e "$OKRED                                                                 === > [ /"
  echo -e "$OKRED                                                                    /   /"
  echo -e "$OKRED                                                                ___ \  /"
  echo -e "$OKRED                                                                    / /"
  echo -e "$OKRED                                                              ____ / /"
  echo -e "$OKRED                                                                   \/$RESET"
  echo ""
  OUT_FILE=$(echo "$TARGET" | tr / -)
  echo -e "${OKGREEN}====================================================================================${RESET}"
  echo -e "$OKRED RUNNING PING DISCOVERY SCAN $RESET"
  echo -e "${OKGREEN}====================================================================================${RESET}"
  nmap -sP $TARGET | tee $LOOT_DIR/domains/sniper-$OUT_FILE-ping-ips.txt
  cat $LOOT_DIR/domains/sniper-$OUT_FILE-ping-ips.txt | grep "scan report" | awk '{print $5}' > $LOOT_DIR/domains/sniper-$OUT_FILE-ping-ips-sorted.txt
  echo -e "${OKGREEN}====================================================================================${RESET}"
  echo -e "$OKRED RUNNING TCP PORT SCAN $RESET"
  echo -e "${OKGREEN}====================================================================================${RESET}"
  nmap -T4 -v -sC -sA -sV -F $TARGET 2>/dev/null | tee $LOOT_DIR/domains/sniper-$OUT_FILE-tcp-ports.txt 2>/dev/null 
  cat $LOOT_DIR/domains/sniper-$OUT_FILE-tcp-ports.txt | grep open | grep on | awk '{print $6}' > $LOOT_DIR/domains/sniper-$OUT_FILE-tcp-ips.txt
  echo -e "${OKGREEN}====================================================================================${RESET}"
  echo -e "$OKRED CURRENT TARGETS $RESET"
  echo -e "${OKGREEN}====================================================================================${RESET}"
  cat $LOOT_DIR/domains/sniper-$OUT_FILE-ping-ips-sorted.txt $LOOT_DIR/domains/sniper-$OUT_FILE-tcp-ips.txt > $LOOT_DIR/domains/sniper-$OUT_FILE-ips-unsorted.txt
  sort -u $LOOT_DIR/domains/sniper-$OUT_FILE-ips-unsorted.txt > $LOOT_DIR/domains/sniper-$OUT_FILE-ips.txt
  cat $LOOT_DIR/domains/sniper-$OUT_FILE-ips.txt
  echo ""
  echo -e "$OKRED[+]$RESET Target list saved to $LOOT_DIR/domains/sniper-$OUT_FILE-ips.txt "
  echo -e "$OKRED[i] To scan all IP's, use sniper -f $LOOT_DIR/domains/sniper-$OUT_FILE-ips.txt -m flyover, airstrike or nuke modes. $RESET"
  echo -e "${OKGREEN}====================================================================================${RESET}"
  echo -e "$OKRED SCAN COMPLETE! $RESET"
  echo -e "${OKGREEN}====================================================================================${RESET}"
  loot
  exit
fi