# FULLPORTONLY MODE
if [[ "$MODE" = "vulnscan" ]]; then
  if [[ "$REPORT" = "1" ]]; then
    args="-t $TARGET"
    if [[ ! -z "$WORKSPACE" ]]; then
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
    sniper $args | tee $LOOT_DIR/output/sniper-$TARGET-$MODE-`date +"%Y%m%d%H%M"`.txt 2>&1
    exit
  fi
  logo

  echo "[sn1persecurity.com] •?((¯°·._.• Started Sn1per scan: $TARGET [$MODE] (`date +"%Y-%m-%d %H:%M"`) •._.·°¯))؟•" >> $LOOT_DIR/scans/notifications_new.txt
  if [[ "$SLACK_NOTIFICATIONS" == "1" ]]; then
    /bin/bash "$INSTALL_DIR/bin/slack.sh" "[sn1persecurity.com] •?((¯°·._.• Started Sn1per scan: $TARGET [$MODE] (`date +"%Y-%m-%d %H:%M"`) •._.·°¯))؟•"
  fi  
  echo "$TARGET" >> $LOOT_DIR/domains/targets.txt
  echo "sniper -t $TARGET -m $MODE --noreport $args" >> $LOOT_DIR/scans/running_${TARGET}_${MODE}.txt 2> /dev/null
  ls -lh $LOOT_DIR/scans/running_*.txt 2> /dev/null | wc -l 2> /dev/null > $LOOT_DIR/scans/tasks-running.txt
  if [[ "$NESSUS" = "1" ]]; then
    echo -e "${OKGREEN}====================================================================================${RESET}•x${OKGREEN}[`date +"%Y-%m-%d](%H:%M)"`${RESET}x•"
    echo -e "$OKRED RUNNING NESSUS VULNERABILITY SCAN $RESET"
    echo -e "${OKGREEN}====================================================================================${RESET}•x${OKGREEN}[`date +"%Y-%m-%d](%H:%M)"`${RESET}x•"
    bash /usr/share/sniper/bin/nessus.sh $TARGET $NESSUS_KEY $NESSUS_HOST $NESSUS_USERNAME $NESSUS_PASSWORD $NESSUS_POLICY_ID $LOOT_DIR
  fi
  if [[ "$OPENVAS" = "1" ]]; then
    sudo openvas-start 2> /dev/null > /dev/null
    echo -e "${OKGREEN}====================================================================================${RESET}•x${OKGREEN}[`date +"%Y-%m-%d](%H:%M)"`${RESET}x•"
    echo -e "$OKRED RUNNING OPENVAS VULNERABILITY SCAN $RESET"
    echo -e "${OKGREEN}====================================================================================${RESET}•x${OKGREEN}[`date +"%Y-%m-%d](%H:%M)"`${RESET}x•"
    echo "Scanning target: $TARGET "
    echo ""
    echo "-----------------------------------------------"
    echo "Listing OpenVAS version..."
    echo "-----------------------------------------------"
    omp -h $OPENVAS_HOST -p $OPENVAS_PORT -u $OPENVAS_USERNAME -w $OPENVAS_PASSWORD -O
    echo ""
    echo "Listing OpenVAS targets..."
    echo "-----------------------------------------------"
    omp -h $OPENVAS_HOST -p $OPENVAS_PORT -u $OPENVAS_USERNAME -w $OPENVAS_PASSWORD -T
    echo ""
    echo "Listing OpenVAS tasks..."
    echo "-----------------------------------------------"
    omp -h $OPENVAS_HOST -p $OPENVAS_PORT -u $OPENVAS_USERNAME -w $OPENVAS_PASSWORD -G
    echo ""
    echo "Creating scan task..."
    echo "-----------------------------------------------"
    ASSET_ID=$(omp -h $OPENVAS_HOST -p $OPENVAS_PORT -u $OPENVAS_USERNAME -w $OPENVAS_PASSWORD --xml="<create_target><name>$TARGET</name><hosts>$TARGET</hosts></create_target>" | xmlstarlet sel -t -v /create_target_response/@id) && echo "ASSET_ID: $ASSET_ID"
    if [[ "$ASSET_ID" == "" ]]; then
      ASSET_ID_ERROR=$(omp -u $OPENVAS_USERNAME -w $OPENVAS_PASSWORD --xml="<create_target><name>$TARGET</name><hosts>$TARGET</hosts></create_target>")
      if [[ "$ASSET_ID_ERROR" == *"Target exists already"* ]]; then
        ASSET_ID=$(omp -u $OPENVAS_USERNAME -w $OPENVAS_PASSWORD -T | grep " $TARGET" | awk '{print $1}')
        echo "ASSET_ID: $ASSET_ID"
      fi
    fi
    TASK_ID=$(omp -h $OPENVAS_HOST -p $OPENVAS_PORT -u $OPENVAS_USERNAME -w $OPENVAS_PASSWORD --xml "<create_task><name>$TARGET</name><preferences><preference><scanner_name>source_iface</scanner_name><value>eth0</value></preference></preferences><config id=\"74db13d6-7489-11df-91b9-002264764cea\"/><target id=\"$ASSET_ID\"/></create_task>" | xmlstarlet sel -t -v /create_task_response/@id) && echo "TASK_ID: $TASK_ID"
    if [[ "TASK_ID" == "" ]]; then
      omp -h $OPENVAS_HOST -p $OPENVAS_PORT -u $OPENVAS_USERNAME -w $OPENVAS_PASSWORD --xml "<create_task><name>$TARGET</name><preferences><preference><scanner_name>source_iface</scanner_name><value>eth0</value></preference></preferences><config id=\"74db13d6-7489-11df-91b9-002264764cea\"/><target id=\"$ASSET_ID\"/></create_task>"
    fi
    REPORT_ID=$(omp -h $OPENVAS_HOST -p $OPENVAS_PORT -u $OPENVAS_USERNAME -w $OPENVAS_PASSWORD --xml "<start_task task_id=\"$TASK_ID\"/>" | cut -d\> -f3 | cut -d\< -f1) && echo "REPORT_ID: $REPORT_ID"
    if [[ "$REPORT_ID" == "" ]]; then
      omp -h $OPENVAS_HOST -p $OPENVAS_PORT -u $OPENVAS_USERNAME -w $OPENVAS_PASSWORD --xml "<start_task task_id=\"$TASK_ID\"/>"
    fi
    echo ""
    resp=""
    while [[ $resp != "Done" && $REPORT_ID != "" ]]
    do
      omp -u $OPENVAS_USERNAME -w $OPENVAS_PASSWORD -G | grep $TASK_ID
      resp=$(omp -h $OPENVAS_HOST -p $OPENVAS_PORT -u $OPENVAS_USERNAME -w $OPENVAS_PASSWORD -G | grep "$TASK_ID" | awk '{print $2}')
      sleep 60
    done
    if [[ $REPORT_ID != "" ]]; then
      omp -h $OPENVAS_HOST -p $OPENVAS_PORT -u $OPENVAS_USERNAME -w $OPENVAS_PASSWORD --xml "<get_reports report_id=\"$REPORT_ID\" format_id=\"6c248850-1f62-11e1-b082-406186ea4fc5\"/>" | cut -d\> -f3 | cut -d\< -f1 | base64 -d > "$LOOT_DIR/output/openvas-$TARGET.html"

      echo "Report saved to $LOOT_DIR/output/openvas-$TARGET.html"
      cat $LOOT_DIR/output/openvas-$TARGET.html 2> /dev/null
    else
      echo "No report ID found. Listing scan tasks:"
      omp -h $OPENVAS_HOST -p $OPENVAS_PORT -u $OPENVAS_USERNAME -w $OPENVAS_PASSWORD -G | grep $TARGET
    fi
  fi
  if [[ "$SC0PE_VULNERABLITY_SCANNER" == "1" ]]; then
      echo -e "${OKGREEN}====================================================================================${RESET}•x${OKGREEN}[`date +"%Y-%m-%d](%H:%M)"`${RESET}x•"
      echo -e "$OKRED RUNNING SC0PE WEB VULNERABILITY SCAN $RESET"
      echo -e "${OKGREEN}====================================================================================${RESET}•x${OKGREEN}[`date +"%Y-%m-%d](%H:%M)"`${RESET}x•"
      SSL="false"
      PORT="80"
      source $INSTALL_DIR/modes/sc0pe-passive-webscan.sh
      source $INSTALL_DIR/modes/sc0pe-active-webscan.sh
      SSL="true"
      PORT="443"
      source $INSTALL_DIR/modes/sc0pe-passive-webscan.sh
      source $INSTALL_DIR/modes/sc0pe-active-webscan.sh

      for file in `ls $INSTALL_DIR/templates/passive/web/recursive/*.sh 2> /dev/null`; do
        source $file
      done

      source $INSTALL_DIR/modes/sc0pe-network-scan.sh
  fi

  source $INSTALL_DIR/modes/sc0pe.sh 

  echo -e "${OKGREEN}====================================================================================${RESET}•x${OKGREEN}[`date +"%Y-%m-%d](%H:%M)"`${RESET}x•"
  echo -e "$OKRED SCAN COMPLETE! $RESET"
  echo -e "${OKGREEN}====================================================================================${RESET}•x${OKGREEN}[`date +"%Y-%m-%d](%H:%M)"`${RESET}x•"
  echo "$TARGET" >> $LOOT_DIR/scans/updated.txt
  rm -f $LOOT_DIR/scans/running_${TARGET}_${MODE}.txt 2> /dev/null
  ls -lh $LOOT_DIR/scans/running_*.txt 2> /dev/null | wc -l 2> /dev/null > $LOOT_DIR/scans/tasks-running.txt
  if [[ "$SLACK_NOTIFICATIONS_NMAP" == "1" ]]; then
    /bin/bash "$INSTALL_DIR/bin/slack.sh" postfile "$LOOT_DIR/nmap/nmap-$TARGET.txt"
    /bin/bash "$INSTALL_DIR/bin/slack.sh" postfile "$LOOT_DIR/nmap/nmap-$TARGET-udp.txt"
  fi
  
  echo "[sn1persecurity.com] •?((¯°·._.• Finished Sn1per scan: $TARGET [$MODE] (`date +"%Y-%m-%d %H:%M"`) •._.·°¯))؟•" >> $LOOT_DIR/scans/notifications_new.txt
  if [[ "$SLACK_NOTIFICATIONS" == "1" ]]; then
    /bin/bash "$INSTALL_DIR/bin/slack.sh" "[sn1persecurity.com] •?((¯°·._.• Finished Sn1per scan: $TARGET [$MODE] (`date +"%Y-%m-%d %H:%M"`) •._.·°¯))؟•"
  fi
  loot
  exit
fi
