# FLYOVER MODE ######################################################################################################
if [ "$MODE" = "flyover" ]; then
  if [ -z "$FILE" ]; then
    logo
    echo "You need to specify a list of targets (ie. -f <targets.txt>) to scan."
    exit
  fi

  if [ "$REPORT" = "1" ]; then
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

    args="$args -m flyover --noreport --noloot"
    TARGET="$a"
    args="$args -f $FILE"
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

    if [ ! -z "$WORKSPACE_DIR" ]; then
      echo "sniper -f $FILE -m $MODE --noreport $args" >> $LOOT_DIR/scans/$WORKSPACE-$MODE.txt
      sniper $args | tee $WORKSPACE_DIR/output/sniper-$WORKSPACE-$MODE-`date +%Y%m%d%H%M`.txt 2>&1
    else
      echo "sniper -f $FILE -m $MODE --noreport $args" >> $LOOT_DIR/scans/$WORKSPACE-$MODE.txt
      sniper $args | tee $LOOT_DIR/output/sniper-$WORKSPACE-$MODE-`date +%Y%m%d%H%M`.txt 2>&1
    fi

    args=""
  fi

  i=1
  for HOST in `sort -u $FILE`; do
    TARGET="$HOST"

    touch $LOOT_DIR/scans/$TARGET-$MODE.txt 2> /dev/null

    echo "$TARGET" >> $LOOT_DIR/domains/targets.txt
    echo -e "$OKRED=====================================================================================$RESET"
    echo -e "${OKBLUE}HOST:$RESET $TARGET"

    dig all +short $TARGET 2> /dev/null > $LOOT_DIR/nmap/dns-$TARGET.txt 2> /dev/null & 
    dig all +short -x $TARGET 2> /dev/null >> $LOOT_DIR/nmap/dns-$TARGET.txt 2> /dev/null & 
    dig A +short $TARGET 2> /dev/null >> $LOOT_DIR/ips/ips-all-unsorted.txt 2> /dev/null &

    wget -qO- -T 1 --connect-timeout=3 --read-timeout=3 --tries=1 http://$TARGET |  perl -l -0777 -ne 'print $1 if /<title.*?>\s*(.*?)\s*<\/title/si' 2> /dev/null > $LOOT_DIR/web/title-https-$TARGET.txt & 2> /dev/null
    wget -qO- -T 1 --connect-timeout=3 --read-timeout=3 --tries=1 https://$TARGET |  perl -l -0777 -ne 'print $1 if /<title.*?>\s*(.*?)\s*<\/title/si' 2> /dev/null > $LOOT_DIR/web/title-https-$TARGET.txt & 2> /dev/null

    curl --connect-timeout 3 -I -s -R http://$TARGET 2> /dev/null > $LOOT_DIR/web/headers-http-$TARGET.txt 2> /dev/null & 
    curl --connect-timeout 3 -I -s -R https://$TARGET 2> /dev/null > $LOOT_DIR/web/headers-https-$TARGET.txt 2> /dev/null &

    webtech -u http://$TARGET 2> /dev/null | grep \- 2> /dev/null | cut -d- -f2- 2> /dev/null > $LOOT_DIR/web/webtech-$TARGET-http.txt 2> /dev/null &
    webtech -u https://$TARGET 2> /dev/null | grep \- 2> /dev/null | cut -d- -f2- 2> /dev/null > $LOOT_DIR/web/webtech-$TARGET-https.txt 2> /dev/null &

    nmap -sS -T5 --open -Pn -p $QUICK_PORTS $TARGET -oX $LOOT_DIR/nmap/nmap-$TARGET.xml 2> /dev/null > $LOOT_DIR/nmap/nmap-$TARGET.txt 2> /dev/null & 

    cat $LOOT_DIR/nmap/dns-$TARGET.txt 2> /dev/null | egrep -i "wordpress|instapage|heroku|github|bitbucket|squarespace|fastly|feed|fresh|ghost|helpscout|helpjuice|instapage|pingdom|surveygizmo|teamwork|tictail|shopify|desk|teamwork|unbounce|helpjuice|helpscout|pingdom|tictail|campaign|monitor|cargocollective|statuspage|tumblr|amazon|hubspot|cloudfront|modulus|unbounce|uservoice|wpengine|cloudapp" 2>/dev/null | tee $LOOT_DIR/nmap/takeovers-$TARGET.txt 2>/dev/null & 2> /dev/null

    if [ ${DISTRO} == "blackarch"  ]; then
      /bin/CutyCapt --url=http://$TARGET:80 --out=$LOOT_DIR/screenshots/$TARGET-port80.jpg --insecure --max-wait=5000 2> /dev/null &
      /bin/CutyCapt --url=https://$TARGET:443 --out=$LOOT_DIR/screenshots/$TARGET-port443.jpg --insecure --max-wait=5000 2> /dev/null &
    else
      cutycapt --url=http://$TARGET:80 --out=$LOOT_DIR/screenshots/$TARGET-port80.jpg --insecure --max-wait=5000 2> /dev/null > /dev/null &
      cutycapt --url=https://$TARGET:443 --out=$LOOT_DIR/screenshots/$TARGET-port443.jpg --insecure --max-wait=5000 2> /dev/null > /dev/null &
    fi

    echo "$TARGET" >> $LOOT_DIR/scans/updated.txt
    
    i=$((i+1))
    if [ "$i" -gt "20" ]; then
      i=0
      sleep 2
    fi
  done

  sort -u $LOOT_DIR/domains/targets.txt 2>/dev/null >> $LOOT_DIR/domains/domains-all-sorted.txt
  sort -u LOOT_DIR/ips/ips-all-unsorted.txt 2> /dev/null > $LOOT_DIR/ips/ips-all-sorted.txt 2> /dev/null
  sleep 20
  rm -f $INSTALL_DIR/wget-log* 2> /dev/null
  echo -e "$OKRED=====================================================================================$RESET"

  if [ "$LOOT" = "1" ]; then
    loot
    exit
  else
    for HOST in `sort -u $LOOT_DIR/domains/domains-all-sorted.txt $LOOT_DIR/domains/targets-all-sorted.txt 2> /dev/null`; do
      TARGET="$HOST"
      echo -e "$OKRED=====================================================================================$RESET"
      echo -e "${OKBLUE}HOST:$RESET $TARGET"
      echo -e "${OKBLUE}DNS:$RESET `cat $LOOT_DIR/nmap/dns-$TARGET.txt 2> /dev/null`"
      echo -e "${OKBLUE}TAKEOVERS:$RESET ${OKRED}" && cat $LOOT_DIR/nmap/takeovers-$TARGET.txt 2> /dev/null
      echo -en "${OKBLUE}TITLE:$RESET ${OKORANGE}" && cat $LOOT_DIR/web/title-htt*-$TARGET.txt 2> /dev/null
      echo "-"
      echo -e "${OKBLUE}HEADERS:$RESET"
      cat $LOOT_DIR/web/headers-htt*-$TARGET.txt 2> /dev/null
      echo -en "${OKBLUE}PORTS:$RESET "
      for PORT in `cat $LOOT_DIR/nmap/nmap-$TARGET.xml 2>/dev/null | egrep 'state="open"' | cut -d' ' -f3 | cut -d\" -f2`; do
        echo -n "$PORT "
      done
      echo ""
      echo "$TARGET" >> $LOOT_DIR/scans/updated.txt
    done
  fi

  sort -u $LOOT_DIR/ips/ips-all-unsorted.txt 2> /dev/null > $LOOT_DIR/ips/ips-all-sorted.txt 2> /dev/null
  exit
fi