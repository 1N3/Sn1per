  if [ $SCAN_TYPE == "DOMAIN" ] && [ $OSINT == "1" ]; then
    if [ $OSINT == "0" ]; then
      echo -e "${OKGREEN}====================================================================================${RESET}"
      echo -e "$OKRED SKIPPING OSINT $RESET"
      echo -e "${OKGREEN}====================================================================================${RESET}"
    else
      if [ "$SLACK_NOTIFICATIONS" == "1" ]; then
        /bin/bash "$INSTALL_DIR/bin/slack.sh" "[xerosecurity.com] •?((¯°·._.• Started Sn1per stage 2 OSINT scan: $TARGET [$MODE] (`date +"%Y-%m-%d %H:%M"`) •._.·°¯))؟•"
      fi
      if [ $GOOHAK = "1" ]; then
        echo -e "${OKGREEN}====================================================================================${RESET}"
        echo -e "$OKRED RUNNING GOOGLE HACKING QUERIES $RESET"
        echo -e "${OKGREEN}====================================================================================${RESET}"
        goohak $TARGET > /dev/null
      fi
      if [ $INURLBR = "1" ]; then
        echo -e "${OKGREEN}====================================================================================${RESET}"
        echo -e "$OKRED RUNNING INURLBR OSINT QUERIES $RESET"
        echo -e "${OKGREEN}====================================================================================${RESET}"
        php /usr/share/sniper/bin/inurlbr.php --dork "site:$TARGET" -s inurlbr-$TARGET | tee $LOOT_DIR/osint/inurlbr-$TARGET
        sed -r "s/\x1B\[([0-9]{1,2}(;[0-9]{1,2})?)?[mGK]//g" $LOOT_DIR/osint/inurlbr-$TARGET > $LOOT_DIR/osint/inurlbr-$TARGET.txt 2> /dev/null
        rm -f $LOOT_DIR/osint/inurlbr-$TARGET
        rm -Rf output/ cookie.txt exploits.conf
      fi
      GHDB="1"
      if [ "$SLACK_NOTIFICATIONS" == "1" ]; then
        /bin/bash "$INSTALL_DIR/bin/slack.sh" "[xerosecurity.com] •?((¯°·._.• Finished Sn1per stage 2 OSINT scan: $TARGET [$MODE] (`date +"%Y-%m-%d %H:%M"`) •._.·°¯))؟•"
      fi
    fi
  fi
