# NUKE MODE #####################################################################################################
if [ "$MODE" = "nuke" ]; then
  if [ -z "$FILE" ]; then
    logo
    echo "You need to specify a list of targets (ie. -f <targets.txt>) to scan."
    exit
  fi
  if [ "$REPORT" = "1" ]; then
    for a in `cat $FILE`;
    do
      if [ ! -z "$WORKSPACE" ]; then
        args="$args -b -re -o -fp -w $WORKSPACE"
        WORKSPACE_DIR=$INSTALL_DIR/loot/workspace/$WORKSPACE
        echo -e "$OKBLUE[*] Saving loot to $WORKSPACE_DIR [$RESET${OKGREEN}OK${RESET}$OKBLUE]$RESET"
        mkdir -p $WORKSPACE_DIR 2> /dev/null
        mkdir $WORKSPACE_DIR/domains 2> /dev/null
        mkdir $WORKSPACE_DIR/screenshots 2> /dev/null
        mkdir $WORKSPACE_DIR/nmap 2> /dev/null
        mkdir $WORKSPACE_DIR/notes 2> /dev/null
        mkdir $WORKSPACE_DIR/reports 2> /dev/null
        mkdir $WORKSPACE_DIR/output 2> /dev/null
      fi
      args="$args --noreport --noloot"
      TARGET="$a"
      args="$args -t $TARGET"
      echo -e "$OKRED "
      echo -e "$OKRED                              ____"
      echo -e "$OKRED                      __,-~~/~    \`---."
      echo -e "$OKRED                    _/_,---(      ,    )"
      echo -e "$OKRED                __ /        <    /   )  \___"
      echo -e "$OKRED - ------===;;;'====------------------===;;;===----- -  -"
      echo -e "$OKRED                   \/  ~'~'~'~'~'~\~'~)~'/"
      echo -e "$OKRED                   (_ (   \  (     >    \)"
      echo -e "$OKRED                    \_( _ <         >_>'"
      echo -e "$OKRED                       ~ \`-i' ::>|--\""
      echo -e "$OKRED                           I;|.|.|"
      echo -e "$OKRED                          <|i::|i|\`."
      echo -e "$OKRED                        (\` ^''\`-' ')"
      echo -e "$OKRED --------------------------------------------------------- $RESET"
      echo -e "$OKORANGE + -- --=[WARNING! Nuking ALL target! $RESET"
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