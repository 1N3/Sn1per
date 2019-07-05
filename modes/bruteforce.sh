if [ "$AUTOBRUTE" = "0" ]; then
  echo -e "${OKGREEN}====================================================================================${RESET}"
  echo -e "$OKRED SKIPPING BRUTE FORCE $RESET"
  echo -e "${OKGREEN}====================================================================================${RESET}"
else
  echo -e "${OKGREEN}====================================================================================${RESET}"
  echo -e "$OKRED RUNNING BRUTE FORCE $RESET"
  echo -e "${OKGREEN}====================================================================================${RESET}"
  if [ "$SLACK_NOTIFICATIONS" == "1" ]; then
    /bin/bash "$INSTALL_DIR/bin/slack.sh" "[xerosecurity.com] •?((¯°·._.• Started Sn1per brute force: $TARGET [$MODE] (`date +"%Y-%m-%d %H:%M"`) •._.·°¯))؟•"
  fi
  brutex $TARGET | tee $LOOT_DIR/credentials/brutex-$TARGET 2> /dev/null
  sed -r "s/\x1B\[([0-9]{1,2}(;[0-9]{1,2})?)?[mGK]//g" $LOOT_DIR/credentials/brutex-$TARGET 2> /dev/null > $LOOT_DIR/credentials/brutex-$TARGET.txt 2> /dev/null
  rm -f $LOOT_DIR/credentials/brutex-$TARGET
  cd $INSTALL_DIR
  rm -f hydra.restore
  rm -f scan.log
  echo ""
  if [ "$SLACK_NOTIFICATIONS_BRUTEFORCE" == "1" ]; then
    /bin/bash "$INSTALL_DIR/bin/slack.sh" postfile "$LOOT_DIR/credentials/brutex-$TARGET.txt"
  fi
  if [ "$SLACK_NOTIFICATIONS" == "1" ]; then
    /bin/bash "$INSTALL_DIR/bin/slack.sh" "[xerosecurity.com] •?((¯°·._.• Finished Sn1per brute force: $TARGET [$MODE] (`date +"%Y-%m-%d %H:%M"`) •._.·°¯))؟•"
  fi
fi