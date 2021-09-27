if [[ "$AUTO_BRUTE" = "1" ]]; then
  echo "sniper -t $TARGET -m $MODE --noreport $args" >> $LOOT_DIR/scans/running_${TARGET}_bruteforce.txt 2> /dev/null
  ls -lh $LOOT_DIR/scans/running_*.txt 2> /dev/null | wc -l 2> /dev/null > $LOOT_DIR/scans/tasks-running.txt
  echo -e "${OKGREEN}====================================================================================${RESET}•x${OKGREEN}[`date +"%Y-%m-%d](%H:%M)"`${RESET}x•"
  echo -e "$OKRED RUNNING BRUTE FORCE $RESET"
  echo -e "${OKGREEN}====================================================================================${RESET}•x${OKGREEN}[`date +"%Y-%m-%d](%H:%M)"`${RESET}x•"
  echo "[sn1persecurity.com] •?((¯°·._.• Started Sn1per brute force: $TARGET [$MODE] (`date +"%Y-%m-%d %H:%M"`) •._.·°¯))؟•" >> $LOOT_DIR/scans/notifications_new.txt
  if [[ "$SLACK_NOTIFICATIONS" == "1" ]]; then
    /bin/bash "$INSTALL_DIR/bin/slack.sh" "[sn1persecurity.com] •?((¯°·._.• Started Sn1per brute force: $TARGET [$MODE] (`date +"%Y-%m-%d %H:%M"`) •._.·°¯))؟•"
  fi
  brutex $TARGET | tee $LOOT_DIR/credentials/brutex-$TARGET 2> /dev/null
  sed -r "s/\x1B\[([0-9]{1,2}(;[0-9]{1,2})?)?[mGK]//g" $LOOT_DIR/credentials/brutex-$TARGET 2> /dev/null > $LOOT_DIR/credentials/brutex-$TARGET.txt 2> /dev/null
  rm -f $LOOT_DIR/credentials/brutex-$TARGET
  cd $INSTALL_DIR
  rm -f hydra.restore
  rm -f scan.log
  CRACKED=$(egrep -h -i -s password $LOOT_DIR/credentials/brutex-$TARGET.txt 2> /dev/null | grep host 2> /dev/null)
  if [[ ${#CRACKED} -ge 5 ]]; then
    echo "$CRACKED" > $LOOT_DIR/output/cracked-$TARGET.txt 2> /dev/null
  fi
  echo ""
  rm -f $LOOT_DIR/scans/running_${TARGET}_bruteforce.txt 2> /dev/null
  ls -lh $LOOT_DIR/scans/running_*.txt 2> /dev/null | wc -l 2> /dev/null > $LOOT_DIR/scans/tasks-running.txt

  if [[ "$SLACK_NOTIFICATIONS_BRUTEFORCE" == "1" ]]; then
    /bin/bash "$INSTALL_DIR/bin/slack.sh" postfile "$LOOT_DIR/credentials/brutex-$TARGET.txt"
  fi
  echo "[sn1persecurity.com] •?((¯°·._.• Finished Sn1per brute force: $TARGET [$MODE] (`date +"%Y-%m-%d %H:%M"`) •._.·°¯))؟•" >> $LOOT_DIR/scans/notifications_new.txt
  if [[ "$SLACK_NOTIFICATIONS" == "1" ]]; then
    /bin/bash "$INSTALL_DIR/bin/slack.sh" "[sn1persecurity.com] •?((¯°·._.• Finished Sn1per brute force: $TARGET [$MODE] (`date +"%Y-%m-%d %H:%M"`) •._.·°¯))؟•"
  fi
else
  echo -e "$OKORANGE + -- --=[ AUTO_BRUTE setting disabled in sniper.conf... skipping.$RESET"
fi