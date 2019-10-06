# FULLPORTONLY MODE
if [ "$MODE" = "vulnscan" ]; then
  
  if [ "$REPORT" = "1" ]; then
    args="-t $TARGET"
    
    if [ ! -z "$WORKSPACE" ]; then
      args="$args -w $WORKSPACE"
      LOOT_DIR=$INSTALL_DIR/loot/workspace/$WORKSPACE
      echo -e "$OKBLUE[*]$RESET Saving loot to $LOOT_DIR [$RESET${OKGREEN}OK${RESET}$OKBLUE]$RESET"
      mkdir -p $LOOT_DIR 2> /dev/null
      mkdir $LOOT_DIR/domains 2> /dev/null
      mkdir $LOOT_DIR/screenshots 2> /dev/null
      mkdir $LOOT_DIR/nmap 2> /dev/null
      mkdir $LOOT_DIR/notes 2> /dev/null
      mkdir $LOOT_DIR/reports 2> /dev/null
      mkdir $LOOT_DIR/scans 2> /dev/null
      mkdir $LOOT_DIR/output 2> /dev/null
    fi

    args="$args --noreport -m vulnscan" 
    echo "$TARGET $MODE `date +"%Y-%m-%d %H:%M"`" 2> /dev/null >> $LOOT_DIR/scans/tasks.txt 2> /dev/null
    echo "sniper -t $TARGET -m $MODE --noreport $args" >> $LOOT_DIR/scans/$TARGET-vulnscan.txt
    echo "sniper -t $TARGET -m $MODE --noreport $args" >> $LOOT_DIR/scans/running-$TARGET-vulnscan.txt
    sniper $args | tee $LOOT_DIR/output/sniper-$TARGET-$MODE-`date +"%Y%m%d%H%M"`.txt 2>&1
    exit
  fi

  logo
  
  if [ "$SLACK_NOTIFICATIONS" == "1" ]; then
    /bin/bash "$INSTALL_DIR/bin/slack.sh" "[xerosecurity.com] •?((¯°·._.• Started Sn1per scan: $TARGET [$MODE] (`date +"%Y-%m-%d %H:%M"`) •._.·°¯))؟•"
  fi
  
  echo "$TARGET" >> $LOOT_DIR/domains/targets.txt

  if [ "$OPENVAS" = "1" ]; then
    echo -e "${OKGREEN}====================================================================================${RESET}•x${OKGREEN}[`date +"%Y-%m-%d](%H:%M)"`${RESET}x•"
    echo -e "$OKRED RUNNING OPENVAS VULNERABILITY SCAN $RESET"
    echo -e "${OKGREEN}====================================================================================${RESET}•x${OKGREEN}[`date +"%Y-%m-%d](%H:%M)"`${RESET}x•"
    ASSET_ID=$(omp -u $OPENVAS_USERNAME -w $OPENVAS_PASSWORD --xml="<create_target><name>$TARGET</name><hosts>$TARGET</hosts></create_target>" | xmlstarlet sel -t -v /create_target_response/@id) && echo "ASSET_ID: $ASSET_ID"
    TASK_ID=$(omp -u $OPENVAS_USERNAME -w $OPENVAS_PASSWORD --xml "<create_task><name>$TARGET</name><preferences><preference><scanner_name>source_iface</scanner_name><value>eth0</value></preference></preferences><config id=\"74db13d6-7489-11df-91b9-002264764cea\"/><target id=\"$ASSET_ID\"/></create_task>" | xmlstarlet sel -t -v /create_task_response/@id) && echo "TASK_ID: $TASK_ID"
    REPORT_ID=$(omp -u $OPENVAS_USERNAME -w $OPENVAS_PASSWORD --xml "<start_task task_id=\"$TASK_ID\"/>" | cut -d\> -f3 | cut -d\< -f1) && echo "REPORT_ID: $REPORT_ID"
    resp=""
    while [[ $resp != "Done" && $REPORT_ID != "" ]]
    do
      omp -u $OPENVAS_USERNAME -w $OPENVAS_PASSWORD -G | grep $TARGET
      resp=$(omp -u $OPENVAS_USERNAME -w $OPENVAS_PASSWORD -G | grep $TARGET | awk '{print $2}')
      sleep 60
    done
    if [ $REPORT_ID != "" ]; then
      omp -u $OPENVAS_USERNAME -w $OPENVAS_PASSWORD --xml "<get_reports report_id=\"$REPORT_ID\" format_id=\"6c248850-1f62-11e1-b082-406186ea4fc5\"/>" | cut -d\> -f3 | cut -d\< -f1 | base64 -d > "$LOOT_DIR/output/openvas-$TARGET.html"

      echo "Report saved to $LOOT_DIR/output/openvas-$TARGET.html"
    else
      echo "No report ID found. Listing scan tasks:"
      omp -u $OPENVAS_USERNAME -w $OPENVAS_PASSWORD -G | grep $TARGET
    fi
  fi
  echo -e "${OKGREEN}====================================================================================${RESET}•x${OKGREEN}[`date +"%Y-%m-%d](%H:%M)"`${RESET}x•"
  echo -e "$OKRED DONE $RESET"
  echo -e "${OKGREEN}====================================================================================${RESET}•x${OKGREEN}[`date +"%Y-%m-%d](%H:%M)"`${RESET}x•"
  echo "$TARGET" >> $LOOT_DIR/scans/updated.txt
  mv $LOOT_DIR/scans/running-$TARGET-vulnscan.txt $LOOT_DIR/scans/finished-$TARGET-vulnscan.txt 2> /dev/null
  if [ "$SLACK_NOTIFICATIONS_NMAP" == "1" ]; then
    /bin/bash "$INSTALL_DIR/bin/slack.sh" postfile "$LOOT_DIR/nmap/nmap-$TARGET.txt"
    /bin/bash "$INSTALL_DIR/bin/slack.sh" postfile "$LOOT_DIR/nmap/nmap-$TARGET-udp.txt"
  fi
  if [ "$SLACK_NOTIFICATIONS" == "1" ]; then
    /bin/bash "$INSTALL_DIR/bin/slack.sh" "[xerosecurity.com] •?((¯°·._.• Finished Sn1per scan: $TARGET [$MODE] (`date +"%Y-%m-%d %H:%M"`) •._.·°¯))؟•"
  fi
  loot
  exit
fi


