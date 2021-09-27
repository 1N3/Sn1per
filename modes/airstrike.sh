# AIRSTRIKE MODE #####################################################################################################
if [[ "$MODE" = "airstrike" ]]; then
  if [[ -z "$FILE" ]]; then
    logo
    echo "You need to specify a list of targets (ie. -f <targets.txt>) to scan."
    exit
  fi
  if [[ "$REPORT" = "1" ]]; then
    for a in `cat $FILE`;
    do
      if [[ "$AUTO_BRUTE" = "1" ]]; then
        args="$args -b"
      fi
      if [[ "$FULLNMAPSCAN" = "1" ]]; then
        args="$args -fp"
      fi
      if [[ "$OSINT" = "1" ]]; then
        args="$args -o"
      fi
      if [[ "$RECON" = "1" ]]; then
        args="$args -re"
      fi
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
      args="$args -m stealth --noreport --noloot"
      TARGET="$a"
      args="$args -t $TARGET"
      echo -e "$OKRED                                         |"
      echo -e "$OKRED                  |                      |"
      echo -e "$OKRED                  |                    -/_\-"
      echo -e "$OKRED                -/_\-   ______________(/ . \)______________"
      echo -e "$OKRED   ____________(/ . \)_____________    \___/     <>"
      echo -e "$OKRED   <>           \___/      <>    <>"
      echo -e "$OKRED "
      echo -e "$OKRED      ||"
      echo -e "$OKRED      <>"
      echo -e "$OKRED                            ||"
      echo -e "$OKRED                            <>"
      echo -e "$OKRED                                       ||"
      echo -e "$OKRED                                       ||            BIG"
      echo -e "$OKRED        _____               __         <>      (^)))^ BOOM!"
      echo -e "$OKRED  BOOM!/((  )\       BOOM!((  )))            (     ( )"
      echo -e "$OKRED ---- (__()__))          (() ) ))           (  (  (   )"
      echo -e "$OKRED     ||  |||____|------    \  (/   ___     (__\     /__)"
      echo -e "$OKRED      |__|||  |     |---|---|||___|   |___-----|||||"
      echo -e "$OKRED  |  ||.  |   |       |     |||                |||||"
      echo -e "$OKRED      |__|||  |     |---|---|||___|   |___-----|||||"
      echo -e "$OKRED  |  ||.  |   |       |     |||                |||||"
      echo -e "$OKRED __________________________________________________________"
      echo -e "$RESET"
      if [[ ! -z "$WORKSPACE_DIR" ]]; then
        echo "$TARGET $MODE `date +"%Y-%m-%d %H:%M"`" 2> /dev/null >> $LOOT_DIR/scans/tasks.txt 2> /dev/null
        echo "sniper -t $TARGET -m $MODE --noreport $args" >> $LOOT_DIR/scans/$TARGET-$MODE.txt
        echo "[sn1persecurity.com] •?((¯°·._.• Started Sn1per scan: $TARGET [$MODE] (`date +"%Y-%m-%d %H:%M"`) •._.·°¯))؟•" >> $LOOT_DIR/scans/notifications_new.txt
        if [[ "$SLACK_NOTIFICATIONS" == "1" ]]; then
          /bin/bash "$INSTALL_DIR/bin/slack.sh" "[sn1persecurity.com] •?((¯°·._.• Started Sn1per scan: $TARGET [$MODE] (`date +"%Y-%m-%d %H:%M"`) •._.·°¯))؟•"
        fi
        sniper $args | tee $WORKSPACE_DIR/output/sniper-$TARGET-$MODE-`date +"%Y%m%d%H%M"`.txt 2>&1
      else
        echo "$TARGET $MODE `date +"%Y-%m-%d %H:%M"`" 2> /dev/null >> $LOOT_DIR/scans/tasks.txt 2> /dev/null
        echo "sniper -t $TARGET -m $MODE --noreport $args" >> $LOOT_DIR/scans/$TARGET-$MODE.txt
        sniper $args | tee $LOOT_DIR/output/sniper-$TARGET-$MODE-`date +"%Y%m%d%H%M"`.txt 2>&1
      fi
      args=""
    done
  fi
  echo "[sn1persecurity.com] •?((¯°·._.• Finished Sn1per scan: $TARGET [$MODE] (`date +"%Y-%m-%d %H:%M"`) •._.·°¯))؟•" >> $LOOT_DIR/scans/notifications_new.txt
  if [[ "$SLACK_NOTIFICATIONS" == "1" ]]; then
    /bin/bash "$INSTALL_DIR/bin/slack.sh" "[sn1persecurity.com] •?((¯°·._.• Finished Sn1per scan: $TARGET [$MODE] (`date +"%Y-%m-%d %H:%M"`) •._.·°¯))؟•"
  fi
  if [[ "$LOOT" = "1" ]]; then
    loot
  fi  
  exit
fi
