# AIRSTRIKE MODE #####################################################################################################
if [ "$MODE" = "airstrike" ]; then
  if [ -z "$FILE" ]; then
    logo
    echo "You need to specify a list of targets (ie. -f <targets.txt>) to scan."
    exit
  fi
  if [ "$REPORT" = "1" ]; then
    for a in `cat $FILE`;
    do
      if [ "$AUTOBRUTE" = "1" ]; then
        args="$args -b"
      fi
      if [ "$FULLNMAPSCAN" = "1" ]; then
        args="$args -fp"
      fi
      if [ "$OSINT" = "1" ]; then
        args="$args -o"
      fi
      if [ "$RECON" = "1" ]; then
        args="$args -re"
      fi
      if [ ! -z "$WORKSPACE" ]; then
        args="$args -w $WORKSPACE"
        WORKSPACE_DIR=$INSTALL_DIR/loot/workspace/$WORKSPACE
        echo -e "$OKBLUE[*] Saving loot to $LOOT_DIR [$RESET${OKGREEN}OK${RESET}$OKBLUE]$RESET"
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
      echo -e "$OKRED Bomb raid (contributed by Michael aka SNOOPY@DRYCAS.CLUB.CC.CMU.EDU)"
      echo -e "$RESET"
      if [ ! -z "$WORKSPACE_DIR" ]; then
        echo "sniper -t $TARGET -m $MODE --noreport $args" >> $LOOT_DIR/scans/$TARGET-$MODE.txt
        sniper $args | tee $WORKSPACE_DIR/output/sniper-$TARGET-$MODE-`date +%Y%m%d%H%M`.txt 2>&1
      else
        echo "sniper -t $TARGET -m $MODE --noreport $args" >> $LOOT_DIR/scans/$TARGET-$MODE.txt
        sniper $args | tee $LOOT_DIR/output/sniper-$TARGET-$MODE-`date +%Y%m%d%H%M`.txt 2>&1
      fi
      args=""
    done
  fi
  if [ "$LOOT" = "1" ]; then
    loot
  fi
  exit
fi

# FULLPORTONLY MODE
if [ "$MODE" = "fullportonly" ]; then

  if [ "$REPORT" = "1" ]; then
    args="-t $TARGET"
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
      mkdir $LOOT_DIR/scans 2> /dev/null
      mkdir $LOOT_DIR/output 2> /dev/null
    fi
    args="$args --noreport -m fullportonly"
    echo "sniper -t $TARGET -m $MODE --noreport $args" >> $LOOT_DIR/scans/$TARGET-$MODE.txt
    sniper $args | tee $LOOT_DIR/output/sniper-$TARGET-$MODE-`date +%Y%m%d%H%M`.txt 2>&1
    exit
  fi

  logo
  echo "$TARGET" >> $LOOT_DIR/domains/targets.txt
  if [ -z "$PORT" ]; then
    nmap -Pn -A -v -T4 -p$DEFAULT_TCP_PORTS $TARGET -oX $LOOT_DIR/nmap/nmap-$TARGET.xml  | tee $LOOT_DIR/nmap/nmap-$TARGET.txt
    echo -e "${OKGREEN}====================================================================================${RESET}"
    echo -e "$OKRED PERFORMING UDP PORT SCAN $RESET"
    echo -e "${OKGREEN}====================================================================================${RESET}"
    nmap -Pn -sU -A -T4 -v -p$DEFAULT_UDP_PORTS $TARGET -oX $LOOT_DIR/nmap/nmap-$TARGET-udp.xml
  else
    echo -e "${OKGREEN}====================================================================================${RESET}"
    echo -e "$OKRED PERFORMING TCP PORT SCAN $RESET"
    echo -e "${OKGREEN}====================================================================================${RESET}"
    nmap -Pn -A -v -T4 -p $PORT $TARGET -oX $LOOT_DIR/nmap/nmap-$TARGET.xml  | tee $LOOT_DIR/nmap/nmap-$TARGET.txt
    echo -e "${OKGREEN}====================================================================================${RESET}"
    echo -e "$OKRED PERFORMING UDP PORT SCAN $RESET"
    echo -e "${OKGREEN}====================================================================================${RESET}"
    nmap -Pn -A -v -T4 -sU -p $PORT -Pn $TARGET -oX $LOOT_DIR/nmap/nmap-$TARGET.xml >> $LOOT_DIR/nmap/nmap-$TARGET.txt
  fi
  echo -e "${OKGREEN}====================================================================================${RESET}"
  echo -e "$OKRED DONE $RESET"
  echo -e "${OKGREEN}====================================================================================${RESET}"
  loot
  exit
fi

if [ "$MODE" = "port" ]; then
  if [ -z "$PORT" ]; then
    echo -e "$OKRED + -- --=[Error: You need to enter a port number. $RESET"
    exit
  fi
fi
