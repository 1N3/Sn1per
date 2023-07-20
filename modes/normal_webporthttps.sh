if [[ "$MODE" = "web" ]]; then
  echo "sniper -t $TARGET -m $MODE --noreport $args" >> $LOOT_DIR/scans/running_${TARGET}_${MODE}.txt 2> /dev/null
  ls -lh $LOOT_DIR/scans/running_*.txt 2> /dev/null | wc -l 2> /dev/null > $LOOT_DIR/scans/tasks-running.txt

  echo "[sn1persecurity.com] •?((¯°·._.• Started Sn1per HTTPS web scan: $TARGET [$MODE] (`date +"%Y-%m-%d %H:%M"`) •._.·°¯))؟•" >> $LOOT_DIR/scans/notifications_new.txt
  if [[ "$SLACK_NOTIFICATIONS" == "1" ]]; then
    /bin/bash "$INSTALL_DIR/bin/slack.sh" "[sn1persecurity.com] •?((¯°·._.• Started Sn1per HTTPS web scan: $TARGET [$MODE] (`date +"%Y-%m-%d %H:%M"`) •._.·°¯))؟•"
  fi
  if [[ "$PASSIVE_SPIDER" == "1" ]]; then
    echo -e "${OKGREEN}====================================================================================${RESET}•x${OKGREEN}[`date +"%Y-%m-%d](%H:%M)"`${RESET}x•"
    echo -e "$OKRED RUNNING PASSIVE WEB SPIDER $RESET"
    echo -e "${OKGREEN}====================================================================================${RESET}•x${OKGREEN}[`date +"%Y-%m-%d](%H:%M)"`${RESET}x•"
    curl -sX GET "http://index.commoncrawl.org/CC-MAIN-2022-33-index?url=*.$TARGET&output=json" -H 'Mozilla/5.0 AppleWebKit/537.36 (KHTML, like Gecko; compatible; Googlebot/2.1; +http://www.google.com/bot.html) Safari/537.36' 2> /dev/null | jq -r .url | egrep -v "null" | tee $LOOT_DIR/web/passivespider-$TARGET.txt 2> /dev/null | head -n 250
  fi
  if [[ "$WAYBACKMACHINE" == "1" ]]; then
    echo -e "${OKGREEN}====================================================================================${RESET}•x${OKGREEN}[`date +"%Y-%m-%d](%H:%M)"`${RESET}x•"
    echo -e "$OKRED FETCHING WAYBACK MACHINE URLS $RESET"
    echo -e "${OKGREEN}====================================================================================${RESET}•x${OKGREEN}[`date +"%Y-%m-%d](%H:%M)"`${RESET}x•"
    curl -sX GET "http://web.archive.org/cdx/search/cdx?url=*.$TARGET/*&output=text&fl=original&collapse=urlkey" | tee $LOOT_DIR/web/waybackurls-$TARGET.txt 2> /dev/null | head -n 250
  fi
  if [[ "$HACKERTARGET" == "1" ]]; then
    echo -e "${OKGREEN}====================================================================================${RESET}•x${OKGREEN}[`date +"%Y-%m-%d](%H:%M)"`${RESET}x•"
    echo -e "$OKRED FETCHING HACKERTARGET URLS $RESET"
    echo -e "${OKGREEN}====================================================================================${RESET}•x${OKGREEN}[`date +"%Y-%m-%d](%H:%M)"`${RESET}x•"
    curl -s GET "https://api.hackertarget.com/pagelinks/?q=https://$TARGET" | egrep -v "API count|no links found|input url is invalid|API count|no links found|input url is invalid|error getting links" | tee $LOOT_DIR/web/hackertarget-https-$TARGET.txt 2> /dev/null | head -n 250
  fi
  if [[ "$GAU" == "1" ]]; then
    echo -e "${OKGREEN}====================================================================================${RESET}•x${OKGREEN}[`date +"%Y-%m-%d](%H:%M)"`${RESET}x•"
    echo -e "$OKRED FETCHING GUA URLS $RESET"
    echo -e "${OKGREEN}====================================================================================${RESET}•x${OKGREEN}[`date +"%Y-%m-%d](%H:%M)"`${RESET}x•"
    gau -subs $TARGET | tee $LOOT_DIR/web/gua-$TARGET.txt 2> /dev/null | head -n 250
  fi
  if [[ "$BLACKWIDOW" == "1" ]]; then
    echo -e "${OKGREEN}====================================================================================${RESET}•x${OKGREEN}[`date +"%Y-%m-%d](%H:%M)"`${RESET}x•"
    echo -e "$OKRED RUNNING ACTIVE WEB SPIDER & APPLICATION SCAN $RESET"
    echo -e "${OKGREEN}====================================================================================${RESET}•x${OKGREEN}[`date +"%Y-%m-%d](%H:%M)"`${RESET}x•"
    touch $LOOT_DIR/web/spider-$TARGET.txt 2>/dev/null
    cp $LOOT_DIR/web/spider-$TARGET.txt $LOOT_DIR/web/spider-$TARGET.bak 2>/dev/null
    blackwidow -u https://$TARGET:443 -l 3 -v n
    cp -f /usr/share/blackwidow/"$TARGET"_443/"$TARGET"_443-*.txt $LOOT_DIR/web/ 2>/dev/null 
    cat /usr/share/blackwidow/"$TARGET"_*/"$TARGET"_*-urls-sorted.txt > $LOOT_DIR/web/spider-$TARGET.txt 2>/dev/null
    cat $LOOT_DIR/web/waybackurls-$TARGET.txt 2> /dev/null >> $LOOT_DIR/web/spider-$TARGET.txt 2>/dev/null
    cat $LOOT_DIR/web/hackertarget-*-$TARGET.txt 2> /dev/null >> $LOOT_DIR/web/spider-$TARGET.txt 2>/dev/null
    cat $LOOT_DIR/web/passivespider-$TARGET.txt 2> /dev/null >> $LOOT_DIR/web/spider-$TARGET.txt 2>/dev/null
    cat $LOOT_DIR/web/gua-$TARGET.txt 2> /dev/null >> $LOOT_DIR/web/spider-$TARGET.txt 2>/dev/null
    sed -ir "s/</\&lh\;/g" $LOOT_DIR/web/spider-$TARGET.txt 2>/dev/null
    mv -f $LOOT_DIR/web/spider-$TARGET.txtr $LOOT_DIR/web/spider-$TARGET.txt 2>/dev/null
    sort -u $LOOT_DIR/web/spider-$TARGET.txt 2>/dev/null > $LOOT_DIR/web/spider-$TARGET.sorted 2>/dev/null
    mv $LOOT_DIR/web/spider-$TARGET.sorted $LOOT_DIR/web/spider-$TARGET.txt 2>/dev/null
    diff $LOOT_DIR/web/spider-$TARGET.bak $LOOT_DIR/web/spider-$TARGET.txt 2> /dev/null | grep "> " 2> /dev/null | awk '{print $2}' 2> /dev/null > $LOOT_DIR/web/spider-new-$TARGET.txt
    if [[ $(wc -c $LOOT_DIR/web/spider-new-$TARGET.txt | awk '{print $1}') > 3 ]]; then
      echo "[sn1persecurity.com] •?((¯°·._.• Spider URL change detected on $TARGET (`date +"%Y-%m-%d %H:%M"`) •._.·°¯))؟•" >> $LOOT_DIR/scans/notifications_new.txt
      head -n 20 $LOOT_DIR/web/spider-new-$TARGET.txt 2> /dev/null >> $LOOT_DIR/scans/notifications_new.txt 2> /dev/null
    fi
    if [[ "$SLACK_NOTIFICATIONS_SPIDER_NEW" == "1" && "SLACK_NOTIFICATIONS" == "1" ]]; then
      /bin/bash "$INSTALL_DIR/bin/slack.sh" postfile "$LOOT_DIR/web/spider-new-$TARGET.txt"
    fi
  fi
  if [[ "$INJECTX" == "1" ]]; then
    rm -f $LOOT_DIR/web/injectx-$TARGET-https.raw 2> /dev/null
    for a in `cat $LOOT_DIR/web/spider-$TARGET.txt 2> /dev/null | grep '?' | grep "https\:" | cut -d '?' -f2 | cut -d '=' -f1 | sort -u`; do for b in `grep $a $LOOT_DIR/web/spider-$TARGET.txt 2> /dev/null | grep "https\:" | head -n 1`; do injectx.py -u $b -vy | tee -a $LOOT_DIR/web/injectx-$TARGET-https.raw; done; done;
    sed -r "s/\x1B\[([0-9]{1,2}(;[0-9]{1,2})?)?[mGK]//g" $LOOT_DIR/web/injectx-$TARGET-https.raw 2> /dev/null > $LOOT_DIR/web/injectx-$TARGET-https.txt
  fi
  source $INSTALL_DIR/modes/static-grep-search.sh
  if [[ "$WEB_JAVASCRIPT_ANALYSIS" == "1" ]]; then
    source $INSTALL_DIR/modes/javascript-analysis.sh
  fi
  touch $LOOT_DIR/web/dirsearch-$TARGET.bak 2> /dev/null
  cp $LOOT_DIR/web/dirsearch-$TARGET.txt $LOOT_DIR/web/dirsearch-$TARGET.bak 2> /dev/null
  if [[ "$WEB_BRUTE_COMMONSCAN" == "1" ]]; then
      echo -e "${OKGREEN}====================================================================================${RESET}•x${OKGREEN}[`date +"%Y-%m-%d](%H:%M)"`${RESET}x•"
      echo -e "$OKRED RUNNING COMMON FILE/DIRECTORY BRUTE FORCE $RESET"
      echo -e "${OKGREEN}====================================================================================${RESET}•x${OKGREEN}[`date +"%Y-%m-%d](%H:%M)"`${RESET}x•"
      if [[ "$DIRSEARCH" == "1" ]]; then
        python3 $PLUGINS_DIR/dirsearch/dirsearch.py -u https://$TARGET -w $WEB_BRUTE_COMMON -x $WEB_BRUTE_EXCLUDE_CODES -F -e "$WEB_BRUTE_EXTENSIONS" -t $THREADS --exclude-texts=Attack Detected,Please contact the system administrator,Page Not Found,URL No Longer Exists --random-agent --output=$LOOT_DIR/web/dirsearch-$TARGET.txt 2> /dev/null
      fi
      if [[ "$GOBUSTER" == "1" ]]; then
          gobuster -u https://$TARGET -w $WEB_BRUTE_COMMON -e | tee $LOOT_DIR/web/gobuster-$TARGET-https-common.txt
      fi
  fi
  if [[ "$WEB_BRUTE_FULLSCAN" == "1" ]]; then
      echo -e "${OKGREEN}====================================================================================${RESET}•x${OKGREEN}[`date +"%Y-%m-%d](%H:%M)"`${RESET}x•"
      echo -e "$OKRED RUNNING FULL FILE/DIRECTORY BRUTE FORCE $RESET"
      echo -e "${OKGREEN}====================================================================================${RESET}•x${OKGREEN}[`date +"%Y-%m-%d](%H:%M)"`${RESET}x•"
      if [[ "$DIRSEARCH" == "1" ]]; then
          python3 $PLUGINS_DIR/dirsearch/dirsearch.py -u https://$TARGET -w $WEB_BRUTE_FULL -x $WEB_BRUTE_EXCLUDE_CODES -F -e "/" -t $THREADS --exclude-texts=Attack Detected,Please contact the system administrator,Page Not Found,URL No Longer Exists --random-agent --output=$LOOT_DIR/web/dirsearch-$TARGET.txt 2> /dev/null
      fi
      if [[ "$GOBUSTER" == "1" ]]; then
          gobuster -u https://$TARGET -w $WEB_BRUTE_FULL -e | tee $LOOT_DIR/web/gobuster-$TARGET-https-full.txt
      fi
  fi
  if [[ "$WEB_BRUTE_EXPLOITSCAN" == "1" ]]; then
      echo -e "${OKGREEN}====================================================================================${RESET}•x${OKGREEN}[`date +"%Y-%m-%d](%H:%M)"`${RESET}x•"
      echo -e "$OKRED RUNNING FILE/DIRECTORY BRUTE FORCE FOR VULNERABILITIES $RESET"
      echo -e "${OKGREEN}====================================================================================${RESET}•x${OKGREEN}[`date +"%Y-%m-%d](%H:%M)"`${RESET}x•"
      if [[ "$DIRSEARCH" == "1" ]]; then
          python3 $PLUGINS_DIR/dirsearch/dirsearch.py -u https://$TARGET -w $WEB_BRUTE_EXPLOITS -x $WEB_BRUTE_EXCLUDE_CODES -F -e "/" -t $THREADS --exclude-texts=Attack Detected,Please contact the system administrator,Page Not Found,URL No Longer Exists --random-agent --output=$LOOT_DIR/web/dirsearch-$TARGET.txt 2> /dev/null
      fi
      if [[ "$GOBUSTER" == "1" ]]; then
          gobuster -u https://$TARGET -w $WEB_BRUTE_EXPLOITS -e | tee $LOOT_DIR/web/gobuster-$TARGET-https-exploits.txt
      fi
  fi
  if [[ "$DIRSEARCH" == "1" ]]; then
      cat $PLUGINS_DIR/dirsearch/reports/$TARGET/* 2> /dev/null
      cat $PLUGINS_DIR/dirsearch/reports/$TARGET/* > $LOOT_DIR/web/dirsearch-$TARGET.txt 2> /dev/null
      sort -u $LOOT_DIR/web/dirsearch-$TARGET.txt 2> /dev/null > $LOOT_DIR/web/dirsearch-$TARGET.sorted 2> /dev/null
      mv $LOOT_DIR/web/dirsearch-$TARGET.sorted $LOOT_DIR/web/dirsearch-$TARGET.txt 2> /dev/null 
      diff $LOOT_DIR/web/dirsearch-$TARGET.bak $LOOT_DIR/web/dirsearch-$TARGET.txt 2> /dev/null | grep "> " 2> /dev/null | awk '{print $2 " " $3 " " $4}' 2> /dev/null > $LOOT_DIR/web/dirsearch-new-$TARGET.txt
      if [[ $(wc -c $LOOT_DIR/web/dirsearch-new-$TARGET.txt| awk '{print $1}') > 3 ]]; then
        echo "[sn1persecurity.com] •?((¯°·._.• Disovered URL change detected on $TARGET (`date +"%Y-%m-%d %H:%M"`) •._.·°¯))؟•" >> $LOOT_DIR/scans/notifications_new.txt
        cat $LOOT_DIR/web/dirsearch-new-$TARGET.txt 2> /dev/null >> $LOOT_DIR/scans/notifications_new.txt 2> /dev/null
      fi
      if [[ "$SLACK_NOTIFICATIONS_DIRSEARCH_NEW" == "1" ]]; then
        /bin/bash "$INSTALL_DIR/bin/slack.sh" postfile "$LOOT_DIR/web/dirsearch-new-$TARGET.txt"
      fi
  fi
  if [[ "$GOBUSTER" == "1" ]]; then
      sort -u $LOOT_DIR/web/webbrute-$TARGET-*.txt 2> /dev/null > $LOOT_DIR/web/webbrute-$TARGET.txt 2> /dev/null
  fi
  wget --connect-timeout=5 --read-timeout=10 --tries=1 https://$TARGET/robots.txt -O $LOOT_DIR/web/robots-$TARGET-https.txt 2> /dev/null
  if [[ "$CLUSTERD" == "1" ]]; then
      echo -e "${OKGREEN}====================================================================================${RESET}•x${OKGREEN}[`date +"%Y-%m-%d](%H:%M)"`${RESET}x•"
      echo -e "$OKRED ENUMERATING WEB SOFTWARE $RESET"
      echo -e "${OKGREEN}====================================================================================${RESET}•x${OKGREEN}[`date +"%Y-%m-%d](%H:%M)"`${RESET}x•"
      clusterd --ssl -i $TARGET 2> /dev/null | tee $LOOT_DIR/web/clusterd-$TARGET-https.txt
  fi
  if [[ "$CMSMAP" == "1" ]]; then
      echo -e "${OKGREEN}====================================================================================${RESET}•x${OKGREEN}[`date +"%Y-%m-%d](%H:%M)"`${RESET}x•"
      echo -e "$OKRED RUNNING CMSMAP $RESET"
      echo -e "${OKGREEN}====================================================================================${RESET}•x${OKGREEN}[`date +"%Y-%m-%d](%H:%M)"`${RESET}x•"
      cmsmap https://$TARGET | tee $LOOT_DIR/web/cmsmap-$TARGET-httpsa.txt
      echo ""
      cmsmap https://$TARGET/wordpress/ | tee $LOOT_DIR/web/cmsmap-$TARGET-httpsb.txt
      echo ""
  fi
  if [[ "$WPSCAN" == "1" ]]; then
      echo -e "${OKGREEN}====================================================================================${RESET}•x${OKGREEN}[`date +"%Y-%m-%d](%H:%M)"`${RESET}x•"
      echo -e "$OKRED RUNNING WORDPRESS VULNERABILITY SCAN $RESET"
      echo -e "${OKGREEN}====================================================================================${RESET}•x${OKGREEN}[`date +"%Y-%m-%d](%H:%M)"`${RESET}x•"
      if [[ "$WP_API_KEY" ]]; then
        wpscan --url https://$TARGET --no-update --disable-tls-checks --api-token $WP_API_KEY 2> /dev/null | tee $LOOT_DIR/web/wpscan-$TARGET-https-port443a.txt
        echo ""
        wpscan --url https://$TARGET/wordpress/ --no-update --disable-tls-checks --api-token $WP_API_KEY 2> /dev/null | tee $LOOT_DIR/web/wpscan-$TARGET-https-port443b.txt
        echo ""
      else
        wpscan --url https://$TARGET --no-update --disable-tls-checks 2> /dev/null | tee $LOOT_DIR/web/wpscan-$TARGET-https-port443a.txt
        echo ""
        wpscan --url https://$TARGET/wordpress/ --no-update --disable-tls-checks 2> /dev/null | tee $LOOT_DIR/web/wpscan-$TARGET-https-port443b.txt
        echo ""
      fi
      sed -r "s/\x1B\[([0-9]{1,2}(;[0-9]{1,2})?)?[mGK]//g" $LOOT_DIR/web/wpscan-$TARGET-https-port443a.raw 2> /dev/null > $LOOT_DIR/web/wpscan-$TARGET-https-port443a.txt
      sed -r "s/\x1B\[([0-9]{1,2}(;[0-9]{1,2})?)?[mGK]//g" $LOOT_DIR/web/wpscan-$TARGET-https-port443b.raw 2> /dev/null > $LOOT_DIR/web/wpscan-$TARGET-https-port443b.txt
      rm -f $LOOT_DIR/web/wpscan-$TARGET-http*.raw 2> /dev/null
  fi
  if [[ "$NIKTO" == "1" ]]; then
    echo -e "${OKGREEN}====================================================================================${RESET}•x${OKGREEN}[`date +"%Y-%m-%d](%H:%M)"`${RESET}x•"
    echo -e "$OKRED RUNNING WEB VULNERABILITY SCAN $RESET"
    echo -e "${OKGREEN}====================================================================================${RESET}•x${OKGREEN}[`date +"%Y-%m-%d](%H:%M)"`${RESET}x•"
    nikto -h https://$TARGET -output $LOOT_DIR/web/nikto-$TARGET-http-port443.txt
    sed -ir "s/</\&lh\;/g" $LOOT_DIR/web/nikto-$TARGET-http-port443.txt
  fi
  if [[ "$SHOCKER" = "1" ]]; then
      echo -e "${OKGREEN}====================================================================================${RESET}•x${OKGREEN}[`date +"%Y-%m-%d](%H:%M)"`${RESET}x•"
      echo -e "$OKRED RUNNING SHELLSHOCK EXPLOIT SCAN $RESET"
      echo -e "${OKGREEN}====================================================================================${RESET}•x${OKGREEN}[`date +"%Y-%m-%d](%H:%M)"`${RESET}x•"
      python3 $PLUGINS_DIR/shocker/shocker.py -H $TARGET --cgilist $PLUGINS_DIR/shocker/shocker-cgi_list --ssl --port 443 | tee $LOOT_DIR/web/shocker-$TARGET-port443.txt
  fi
  if [[ "$JEXBOSS" = "1" ]]; then
      echo -e "${OKGREEN}====================================================================================${RESET}•x${OKGREEN}[`date +"%Y-%m-%d](%H:%M)"`${RESET}x•"
      echo -e "$OKRED RUNNING JEXBOSS $RESET"
      echo -e "${OKGREEN}====================================================================================${RESET}•x${OKGREEN}[`date +"%Y-%m-%d](%H:%M)"`${RESET}x•"
      cd /tmp/
      python3 /usr/share/sniper/plugins/jexboss/jexboss.py -u https://$TARGET | tee $LOOT_DIR/web/jexboss-$TARGET-port443.raw
      sed -r "s/\x1B\[([0-9]{1,2}(;[0-9]{1,2})?)?[mGK]//g" $LOOT_DIR/web/jexboss-$TARGET-port443.raw > $LOOT_DIR/web/jexboss-$TARGET-port443.txt 2> /dev/null
      rm -f $LOOT_DIR/web/jexboss-$TARGET-port443.raw 2> /dev/null
      cd $INSTALL_DIR
  fi
  if [[ "$SMUGGLER" = "1" ]]; then
    echo -e "${OKGREEN}====================================================================================${RESET}•x${OKGREEN}[`date +"%Y-%m-%d](%H:%M)"`${RESET}x•"
    echo -e "$OKRED RUNNING HTTP REQUEST SMUGGLING DETECTION $RESET"
    echo -e "${OKGREEN}====================================================================================${RESET}•x${OKGREEN}[`date +"%Y-%m-%d](%H:%M)"`${RESET}x•"
    python3 /usr/share/sniper/plugins/smuggler/smuggler.py --no-color -u https://$TARGET | tee $LOOT_DIR/web/smuggler-$TARGET-port443.txt
  fi
  if [[ "$NUCLEI" = "1" ]]; then
    echo -e "${OKGREEN}====================================================================================${RESET}•x${OKGREEN}[`date +"%Y-%m-%d](%H:%M)"`${RESET}x•"
    echo -e "$OKRED RUNNING NUCLEI SCAN $RESET"
    echo -e "${OKGREEN}====================================================================================${RESET}•x${OKGREEN}[`date +"%Y-%m-%d](%H:%M)"`${RESET}x•"
    nuclei -silent -t /usr/share/sniper/plugins/nuclei-templates/ -c $THREADS -target https://$TARGET -o $LOOT_DIR/web/nuclei-https-10.0.0.19-port443.txt 
  fi
  rm -f $LOOT_DIR/scans/running_${TARGET}_${MODE}.txt 2> /dev/null
  ls -lh $LOOT_DIR/scans/running_*.txt 2> /dev/null | wc -l 2> /dev/null > $LOOT_DIR/scans/tasks-running.txt
  echo "[sn1persecurity.com] •?((¯°·._.• Finished Sn1per HTTPS web scan: $TARGET [$MODE] (`date +"%Y-%m-%d %H:%M"`) •._.·°¯))؟•" >> $LOOT_DIR/scans/notifications_new.txt
  if [[ "$SLACK_NOTIFICATIONS" == "1" ]]; then
    /bin/bash "$INSTALL_DIR/bin/slack.sh" "[sn1persecurity.com] •?((¯°·._.• Finished Sn1per HTTPS web scan: $TARGET [$MODE] (`date +"%Y-%m-%d %H:%M"`) •._.·°¯))؟•"
  fi  
fi
