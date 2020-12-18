# MASSWEB MODE #####################################################################################################
if [[ "$MODE" = "masswebscan" ]]; then
  if [[ -z "$FILE" ]]; then
    logo
    echo "You need to specify a list of targets (ie. -f <targets.txt>) to scan."
    exit
  fi
  if [[ "$REPORT" = "1" ]]; then
    for a in `cat $FILE`;
    do
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
        mkdir $WORKSPACE_DIR/vulnerabilities/ 2> /dev/null
        mkdir $WORKSPACE_DIR/scans/ 2> /dev/null
      fi
      args="$args -m webscan --noreport --noloot"
      TARGET="$a"
      args="$args -t $TARGET"
      if [[ ! -z "$WORKSPACE_DIR" ]]; then
        echo "sniper -t $TARGET -m $MODE --noreport $args" >> $LOOT_DIR/scans/$TARGET-$MODE.txt
        echo "[xerosecurity.com] •?((¯°·._.• Started Sn1per scan: $TARGET [$MODE] (`date +"%Y-%m-%d %H:%M"`) •._.·°¯))؟•" >> $LOOT_DIR/scans/notifications_new.txt
        if [[ "$SLACK_NOTIFICATIONS" == "1" ]]; then
          /bin/bash "$INSTALL_DIR/bin/slack.sh" "[xerosecurity.com] •?((¯°·._.• Started Sn1per scan: $TARGET [$MODE] (`date +"%Y-%m-%d %H:%M"`) •._.·°¯))؟•"
        fi
        sniper $args | tee $WORKSPACE_DIR/output/sniper-$TARGET-$MODE-`date +"%Y%m%d%H%M"`.txt 2>&1
      else
        echo "sniper -t $TARGET -m $MODE --noreport $args" >> $LOOT_DIR/scans/$TARGET-$MODE.txt
        sniper $args | tee $LOOT_DIR/output/sniper-$TARGET-$MODE-`date +"%Y%m%d%H%M"`.txt 2>&1
      fi
      args=""
    done
  fi

  echo "[xerosecurity.com] •?((¯°·._.• Finished Sn1per scan: $TARGET [$MODE] (`date +"%Y-%m-%d %H:%M"`) •._.·°¯))؟•" >> $LOOT_DIR/scans/notifications_new.txt
  if [[ "$SLACK_NOTIFICATIONS" == "1" ]]; then
    /bin/bash "$INSTALL_DIR/bin/slack.sh" "[xerosecurity.com] •?((¯°·._.• Finished Sn1per scan: $TARGET [$MODE] (`date +"%Y-%m-%d %H:%M"`) •._.·°¯))؟•"
  fi
  
  if [[ "$LOOT" = "1" ]]; then
    loot
  fi
  
  exit
fi
