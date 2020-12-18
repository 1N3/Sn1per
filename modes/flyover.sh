# FLYOVER MODE ######################################################################################################
if [[ "$MODE" = "flyover" ]]; then
  if [[ -z "$FILE" ]]; then
    logo
    echo "You need to specify a list of targets (ie. -f <targets.txt>) to scan."
    exit
  fi

  if [[ "$REPORT" = "1" ]]; then
    if [[ ! -z "$WORKSPACE" ]]; then
      args="$args -w $WORKSPACE"
      WORKSPACE_DIR=$INSTALL_DIR/loot/workspace/$WORKSPACE
      echo -e "$OKBLUE[*]$RESET Saving loot to $LOOT_DIR [$RESET${OKGREEN}OK${RESET}$OKBLUE]$RESET"
      mkdir -p $WORKSPACE_DIR 2> /dev/null
      mkdir $WORKSPACE_DIR/domains 2> /dev/null
      mkdir $WORKSPACE_DIR/screenshots 2> /dev/null
      mkdir $WORKSPACE_DIR/nmap 2> /dev/null
      mkdir $WORKSPACE_DIR/notes 2> /dev/null
      mkdir $WORKSPACE_DIR/reports 2> /dev/null
      mkdir $WORKSPACE_DIR/output 2> /dev/null
    fi

    args="$args -f $FILE -m flyover --noreport --noloot"
    echo -e "$OKRED "
    echo -e "$OKRED                     .                             .                           "
    echo -e "$OKRED                    //                             "'\\\\                          '
    echo -e "$OKRED                   //                               "'\\\\                         '
    echo -e "$OKRED                  //                                 "'\\\\                        '
    echo -e "$OKRED                 //                _._                "'\\\\                      '
    echo -e "$OKRED              .---.              .//|"'\\\\.              .---.                    '
    echo -e "$OKRED    ________ / .-. \_________..-~ _.-._ ~-..________ / .-. \_________ -sr      "
    echo -e "$OKRED             \ ~-~ /   /H-     \`-=.___.=-'     -H\   \ ~-~ /                   "
    echo -e "$OKRED               ~~~    / H          [H]          H \    ~~~                     "
    echo -e "$OKRED                     / _H_         _H_         _H_ \                           "
    echo -e "$OKRED                       UUU         UUU         UUU     "
    echo -e "$OKRED "
    echo -e "$RESET"
    echo "sniper -f $FILE -m $MODE --noreport $args" >> $LOOT_DIR/scans/$WORKSPACE-$MODE.txt
    sniper $args | tee $WORKSPACE_DIR/output/sniper-$WORKSPACE-$MODE-`date +"%Y%m%d%H%M"`.txt 2>&1
    echo "$FILE $MODE `date +"%Y-%m-%d %H:%M"`" 2> /dev/null >> $LOOT_DIR/scans/tasks.txt 2> /dev/null
    echo "sniper -f $FILE -m $MODE --noreport $args" >> $LOOT_DIR/scans/running_${WORKSPACE}_${MODE}.txt
    ls -lh $LOOT_DIR/scans/running_*.txt 2> /dev/null | wc -l 2> /dev/null > $LOOT_DIR/scans/tasks-running.txt
    echo "[xerosecurity.com] •?((¯°·._.• Started Sn1per scan: $FILE [$MODE] (`date +"%Y-%m-%d %H:%M"`) •._.·°¯))؟•" >> $LOOT_DIR/scans/notifications_new.txt
    if [[ "$SLACK_NOTIFICATIONS" == "1" ]]; then
      /bin/bash "$INSTALL_DIR/bin/slack.sh" "[xerosecurity.com] •?((¯°·._.• Started Sn1per scan: $FILE [$MODE] (`date +"%Y-%m-%d %H:%M"`) •._.·°¯))؟•"
    fi
    args=""
    cp $LOOT_DIR/nmap/livehosts-sorted.txt $LOOT_DIR/nmap/livehosts-sorted.old 2> /dev/null
    i=1

    echo -e "${OKGREEN}====================================================================================${RESET}•x${OKGREEN}[`date +"%Y-%m-%d](%H:%M)"`${RESET}x•"
    echo -e "$OKBLUE[$RESET${OKRED}i${RESET}$OKBLUE]${RESET} Collecting DNS, ports, HTTP info and screenshots in background.${RESET}"
    echo -e "$OKBLUE[$RESET${OKRED}i${RESET}$OKBLUE]${RESET} All collected info will be saved to ${OKRED}${LOOT_DIR}${RESET}"
    echo -e "$OKBLUE[$RESET${OKRED}i${RESET}$OKBLUE]${RESET} FLYOVER_MAX_HOSTS=$FLYOVER_MAX_HOSTS ${RESET}"
    echo -e "$OKBLUE[$RESET${OKRED}i${RESET}$OKBLUE]${RESET} FLYOVER_DELAY=$FLYOVER_DELAY ${RESET}"
    
    for HOST in `cat $FILE`; do
      TARGET="$HOST"
      echo "$TARGET $MODE `date +"%Y-%m-%d %H:%M"`" 2> /dev/null >> $LOOT_DIR/scans/tasks.txt 2> /dev/null
      touch $LOOT_DIR/scans/$TARGET-$MODE.txt 2> /dev/null
      echo "$TARGET" >> $LOOT_DIR/domains/targets.txt
      echo "sniper -t $TARGET -m $MODE $args" >> $LOOT_DIR/scans/running_${TARGET}_${MODE}.txt 2> /dev/null
      ls -lh $LOOT_DIR/scans/running_*.txt 2> /dev/null | wc -l 2> /dev/null > $LOOT_DIR/scans/tasks-running.txt
      echo -e "${OKGREEN}====================================================================================${RESET}•x${OKGREEN}[`date +"%Y-%m-%d](%H:%M)"`${RESET}x•"
      echo -e "$OKBLUE[*]$RESET SCANNING:$RESET $OKBLUE[$RESET${OKGREEN}${TARGET}${RESET}$OKBLUE]$RESET"
      dig all +short $TARGET 2> /dev/null > $LOOT_DIR/nmap/dns-$TARGET.txt 2> /dev/null & 
      dig all +short -x $TARGET 2> /dev/null >> $LOOT_DIR/nmap/dns-$TARGET.txt 2> /dev/null & 
      wget -qO- -T 1 --connect-timeout=5 --read-timeout=5 --tries=1 http://$TARGET |  perl -l -0777 -ne 'print $1 if /<title.*?>\s*(.*?)\s*<\/title/si' 2> /dev/null > $LOOT_DIR/web/title-http-$TARGET.txt & 2> /dev/null
      wget -qO- -T 1 --connect-timeout=5 --read-timeout=5 --tries=1 https://$TARGET |  perl -l -0777 -ne 'print $1 if /<title.*?>\s*(.*?)\s*<\/title/si' 2> /dev/null > $LOOT_DIR/web/title-https-$TARGET.txt & 2> /dev/null
      curl --connect-timeout 5 -I -s -R --insecure http://$TARGET 2> /dev/null > $LOOT_DIR/web/headers-http-$TARGET.txt 2> /dev/null & 
      curl --connect-timeout 5 -I -s -R --insecure https://$TARGET 2> /dev/null > $LOOT_DIR/web/headers-https-$TARGET.txt 2> /dev/null &
      curl --connect-timeout 5 -s -R -L --insecure http://$TARGET > $LOOT_DIR/web/websource-http-$TARGET.txt 2> /dev/null &
      curl --connect-timeout 5 -s -R -L --insecure https://$TARGET > $LOOT_DIR/web/websource-https-$TARGET.txt 2> /dev/null &
      webtech -u http://$TARGET 2> /dev/null | grep \- 2> /dev/null | cut -d- -f2- 2> /dev/null > $LOOT_DIR/web/webtech-$TARGET-http.txt 2> /dev/null &
      webtech -u https://$TARGET 2> /dev/null | grep \- 2> /dev/null | cut -d- -f2- 2> /dev/null > $LOOT_DIR/web/webtech-$TARGET-https.txt 2> /dev/null &
      mv -f $LOOT_DIR/nmap/ports-$TARGET.txt $LOOT_DIR/nmap/ports-$TARGET.old 2> /dev/null
      nmap -sS -p $QUICK_PORTS $TARGET -oX $LOOT_DIR/nmap/nmap-$TARGET.xml 2> /dev/null > $LOOT_DIR/nmap/nmap-$TARGET.txt 2> /dev/null & 
      WEBHOST=$(cat $LOOT_DIR/nmap/nmap-$TARGET.txt 2> /dev/null | egrep "80|443" | grep open | wc -l 2> /dev/null) 
      if [[ "$WEBHOST" -gt "0" ]]; then
        echo "$TARGET" >> $LOOT_DIR/web/webhosts-unsorted.txt 2> /dev/null
      fi
      cat $LOOT_DIR/nmap/dns-$TARGET.txt 2> /dev/null | egrep -i "anima|bitly|wordpress|instapage|heroku|github|bitbucket|squarespace|fastly|feed|fresh|ghost|helpscout|helpjuice|instapage|pingdom|surveygizmo|teamwork|tictail|shopify|desk|teamwork|unbounce|helpjuice|helpscout|pingdom|tictail|campaign|monitor|cargocollective|statuspage|tumblr|amazon|hubspot|cloudfront|modulus|unbounce|uservoice|wpengine|cloudapp" 2>/dev/null | tee $LOOT_DIR/nmap/takeovers-$TARGET.txt 2>/dev/null & 2> /dev/null
      if [[ $CUTYCAPT = "1" ]]; then
        if [[ $DISTRO == "blackarch"  ]]; then
          /bin/CutyCapt --url=http://$TARGET:80 --out=$LOOT_DIR/screenshots/$TARGET-port80.jpg --insecure --max-wait=5000 2> /dev/null &
          /bin/CutyCapt --url=https://$TARGET:443 --out=$LOOT_DIR/screenshots/$TARGET-port443.jpg --insecure --max-wait=5000 2> /dev/null &
        else
          cutycapt --url=http://$TARGET:80 --out=$LOOT_DIR/screenshots/$TARGET-port80.jpg --insecure --max-wait=5000 2> /dev/null > /dev/null &
          cutycapt --url=https://$TARGET:443 --out=$LOOT_DIR/screenshots/$TARGET-port443.jpg --insecure --max-wait=5000 2> /dev/null > /dev/null &
        fi
      fi
      if [[ $WEBSCREENSHOT = "1" ]]; then
        cd $LOOT_DIR
        python2 $INSTALL_DIR/bin/webscreenshot.py -r chromium http://$TARGET:80 2> /dev/null > /dev/null &
        python2 $INSTALL_DIR/bin/webscreenshot.py -r chromium https://$TARGET:443 2> /dev/null > /dev/null &
      fi
      echo "$TARGET" >> $LOOT_DIR/scans/updated.txt
      echo "$TARGET" >> $LOOT_DIR/domains/targets-all-presorted.txt
      rm -f $LOOT_DIR/scans/running_${TARGET}_${MODE}.txt 2> /dev/null
      ls -lh $LOOT_DIR/scans/running_*.txt 2> /dev/null | wc -l 2> /dev/null > $LOOT_DIR/scans/tasks-running.txt 2> /dev/null
      RUNNING_TASKS=$(wc -l $LOOT_DIR/scans/tasks-running.txt 2> /dev/null)

      i=$((i+1))
      if [[ "$i" -gt "$FLYOVER_MAX_HOSTS" ]]; then
        i=1
        sleep $FLYOVER_DELAY
      fi
    done
    sleep $FLYOVER_DELAY
    sort -u LOOT_DIR/ips/ips-all-unsorted.txt 2> /dev/null > $LOOT_DIR/ips/ips-all-sorted.txt 2> /dev/null
    sort -u $LOOT_DIR/domains/targets-all-presorted.txt 2> /dev/null > $LOOT_DIR/domains/targets-all-sorted.txt
    rm -f $INSTALL_DIR/wget-log* 2> /dev/null
    killall webtech 2> /dev/null
    rm -f $LOOT_DIR/nmap/livehosts-unsorted.txt 2> /dev/null
    for TARGET in `cat $LOOT_DIR/domains/targets-all-sorted.txt`; do
      HOST_UP=$(cat $LOOT_DIR/nmap/nmap-$TARGET.txt 2> /dev/null | grep "host up" 2> /dev/null)
      if [[ ${#HOST_UP} -ge 2 ]]; then
        echo "$TARGET" >> $LOOT_DIR/nmap/livehosts-unsorted.txt 2> /dev/null
      fi
      for PORT in `cat $LOOT_DIR/nmap/nmap-$TARGET.xml $LOOT_DIR/nmap/nmap-$TARGET-*.xml 2>/dev/null | egrep 'state="open"' | cut -d' ' -f3 | cut -d\" -f2 | sort -u | grep '[[:digit:]]'`; do
        echo "$PORT " >> $LOOT_DIR/nmap/ports-$TARGET.txt 
      done
      cat $LOOT_DIR/nmap/nmap-$TARGET.txt $LOOT_DIR/nmap/nmap-$TARGET-*.txt 2>/dev/null | egrep "MAC Address:" | awk '{print $3 " " $4 " " $5 " " $6}' > $LOOT_DIR/nmap/macaddress-$TARGET.txt 2> /dev/null
      cat $LOOT_DIR/nmap/nmap-$TARGET.txt $LOOT_DIR/nmap/nmap-$TARGET-*.txt $LOOT_DIR/output/nmap-$TARGET-*.txt 2>/dev/null | egrep "OS details:|OS guesses:" | cut -d\: -f2 | sed 's/,//g' | head -c50 - > $LOOT_DIR/nmap/osfingerprint-$TARGET.txt 2> /dev/null
      diff $LOOT_DIR/nmap/ports-$TARGET.old $LOOT_DIR/nmap/ports-$TARGET.txt 2> /dev/null > $LOOT_DIR/nmap/ports-$TARGET.diff 2> /dev/null
    done
    sort -u $LOOT_DIR/nmap/livehosts-unsorted.txt 2> /dev/null > $LOOT_DIR/nmap/livehosts-sorted.txt 2> /dev/null
    diff $LOOT_DIR/nmap/livehosts-sorted.old $LOOT_DIR/nmap/livehosts-sorted.txt 2> /dev/null > $LOOT_DIR/nmap/livehosts-sorted.diff 2> /dev/null

    if [[ -s "$LOOT_DIR/nmap/livehosts-sorted.diff" ]]; then
      echo "[xerosecurity.com] •?((¯°·._.• Host status change detected on $TARGET (`date +"%Y-%m-%d %H:%M"`) •._.·°¯))؟•" >> $LOOT_DIR/scans/notifications_new.txt
      cat $LOOT_DIR/nmap/livehosts-sorted.diff | egrep "<|>" >> $LOOT_DIR/scans/notifications_new.txt
      if [[ "$SLACK_NOTIFICATIONS_NMAP_DIFF" == "1" ]]; then
        /bin/bash "$INSTALL_DIR/bin/slack.sh" "[xerosecurity.com] •?((¯°·._.• Host status change detected on $WORKSPACE (`date +"%Y-%m-%d %H:%M"`) •._.·°¯))؟•"
        /bin/bash "$INSTALL_DIR/bin/slack.sh" postfile "$LOOT_DIR/nmap/livehosts-sorted.diff"
      fi
    fi

    for a in `cat $LOOT_DIR/domains/targets-all-sorted.txt 2> /dev/null`
    do
      diff $LOOT_DIR/nmap/ports-$a.old $LOOT_DIR/nmap/ports-$a.txt 2> /dev/null > $LOOT_DIR/nmap/ports-$a.diff 2> /dev/null
      if [[ -s "$LOOT_DIR/nmap/ports-$a.diff" ]]; then
        echo "[xerosecurity.com] •?((¯°·._.• Port change detected on $a (`date +"%Y-%m-%d %H:%M"`) •._.·°¯))؟•" >> $LOOT_DIR/scans/notifications_new.txt
        cat $LOOT_DIR/nmap/ports-$a.diff | egrep "<|>" >> $LOOT_DIR/scans/notifications_new.txt
        if [[ "$SLACK_NOTIFICATIONS_NMAP_DIFF" == "1" ]]; then
          /bin/bash "$INSTALL_DIR/bin/slack.sh" "[xerosecurity.com] •?((¯°·._.• Port change detected on $a (`date +"%Y-%m-%d %H:%M"`) •._.·°¯))؟•"
          /bin/bash "$INSTALL_DIR/bin/slack.sh" postfile "$LOOT_DIR/nmap/ports-$a.diff"
        fi
      fi
    done
    sed -i -E 's/,//g' $LOOT_DIR/ips/ips-all-sorted.txt 2> /dev/null
    rm -f $LOOT_DIR/scans/running_${WORKSPACE}_${MODE}.txt 2> /dev/null
    ls -lh $LOOT_DIR/scans/running_*.txt 2> /dev/null | wc -l 2> /dev/null > $LOOT_DIR/scans/tasks-running.txt
    echo -e "${OKGREEN}====================================================================================${RESET}•x${OKGREEN}[`date +"%Y-%m-%d](%H:%M)"`${RESET}x•"
    echo "[xerosecurity.com] •?((¯°·._.• Finished Sn1per scan: $FILE [$MODE] (`date +"%Y-%m-%d %H:%M"`) •._.·°¯))؟•" >> $LOOT_DIR/scans/notifications_new.txt
    if [[ "$SLACK_NOTIFICATIONS" == "1" ]]; then
      /bin/bash "$INSTALL_DIR/bin/slack.sh" "[xerosecurity.com] •?((¯°·._.• Finished Sn1per scan: $FILE [$MODE] (`date +"%Y-%m-%d %H:%M"`) •._.·°¯))؟•"
    fi
    if [[ "$LOOT" = "1" ]]; then
      loot
    fi
    
  fi
  exit
fi
