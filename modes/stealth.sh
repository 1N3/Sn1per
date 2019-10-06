# STEALTH MODE #####################################################################################################
if [ "$MODE" = "stealth" ]; then
  if [ "$REPORT" = "1" ]; then
    args="-t $TARGET"
    if [ "$OSINT" = "1" ]; then
      args="$args -o"
    fi
    if [ "$AUTOBRUTE" = "1" ]; then
      args="$args -b"
    fi
    if [ "$FULLNMAPSCAN" = "1" ]; then
      args="$args -fp"
    fi
    if [ "$RECON" = "1" ]; then
      args="$args -re"
    fi
    if [ ! -z "$WORKSPACE" ]; then
      args="$args -w $WORKSPACE"
      LOOT_DIR=$INSTALL_DIR/loot/workspace/$WORKSPACE
      echo -e "$OKBLUE[*]$RESET Saving loot to $LOOT_DIR $OKBLUE[$RESET${OKGREEN}OK${RESET}$OKBLUE]$RESET"
      mkdir -p $LOOT_DIR 2> /dev/null
      mkdir $LOOT_DIR/domains 2> /dev/null
      mkdir $LOOT_DIR/screenshots 2> /dev/null
      mkdir $LOOT_DIR/nmap 2> /dev/null
      mkdir $LOOT_DIR/notes 2> /dev/null
      mkdir $LOOT_DIR/reports 2> /dev/null
      mkdir $LOOT_DIR/scans 2> /dev/null
      mkdir $LOOT_DIR/output 2> /dev/null
    fi
    args="$args --noreport -m stealth"
    echo "$TARGET $MODE `date +"%Y-%m-%d %H:%M"`" 2> /dev/null >> $LOOT_DIR/scans/tasks.txt 2> /dev/null
    echo "sniper -t $TARGET -m $MODE --noreport $args" >> $LOOT_DIR/scans/$TARGET-$MODE.txt
    echo "sniper -t $TARGET -m $MODE --noreport $args" >> $LOOT_DIR/scans/running-$TARGET-stealth.txt
    if [ "$SLACK_NOTIFICATIONS" == "1" ]; then
      /bin/bash "$INSTALL_DIR/bin/slack.sh" "[xerosecurity.com] •?((¯°·._.• Started Sn1per scan: $TARGET [$MODE] (`date +"%Y-%m-%d %H:%M"`) •._.·°¯))؟•"
    fi
    sniper $args | tee $LOOT_DIR/output/sniper-$TARGET-$MODE-`date +"%Y%m%d%H%M"`.txt 2>&1
    exit
  fi
  echo -e "$OKRED                ____               $RESET"
  echo -e "$OKRED    _________  /  _/___  ___  _____$RESET"
  echo -e "$OKRED   / ___/ __ \ / // __ \/ _ \/ ___/$RESET"
  echo -e "$OKRED  (__  ) / / // // /_/ /  __/ /    $RESET"
  echo -e "$OKRED /____/_/ /_/___/ .___/\___/_/     $RESET"
  echo -e "$OKRED               /_/                 $RESET"
  echo -e "$RESET"
  echo -e "$OKORANGE + -- --=[ https://xerosecurity.com"
  echo -e "$OKORANGE + -- --=[ Sn1per v$VER by @xer0dayz"
  echo -e "$OKRED "   
  echo -e "$OKRED     ./\."
  echo -e "$OKRED   ./    '\."
  echo -e "$OKRED   \.       '\."
  echo -e "$OKRED     '\.       '\."
  echo -e "$OKRED        '\.       '\."
  echo -e "$OKRED           '\.       '\."
  echo -e "$OKRED           ./           '\."
  echo -e "$OKRED         ./            ____'\."
  echo -e "$OKRED       ./                  <  '\."
  echo -e "$OKRED       \-------\            '>   '\."
  echo -e "$OKRED         '\=====>        ___<       '\."
  echo -e "$OKRED        ./-----/             __________'\."
  echo -e "$OKRED "'       \.------\       _____   ___(_)(_\."\'
  echo -e "$OKRED          '\=====>          <            ./'"
  echo -e "$OKRED         ./-----/            '>        ./"
  echo -e "$OKRED         \.               ___<       ./"
  echo -e "$OKRED           '\.                     ./"
  echo -e "$OKRED              '\.                ./"
  echo -e "$OKRED                 '\.           ./"
  echo -e "$OKRED                 ./          ./"
  echo -e "$OKRED               ./          ./  Carl Pilcher"
  echo -e "$OKRED             ./          ./"
  echo -e "$OKRED           ./          ./"
  echo -e "$OKRED         ./          ./"
  echo -e "$OKRED         \.        ./"
  echo -e "$OKRED           '\.   ./"
  echo -e "$OKRED              '\/"
  echo -e "$RESET"
  echo -e "$OKORANGE + -- --=[ Launching stealth scan: $TARGET $RESET"
  echo -e "$OKGREEN $RESET"
  echo "$TARGET" >> $LOOT_DIR/domains/targets.txt
  echo -e "${OKGREEN}==================================================================================${RESET}•x${OKGREEN}[`date +"%Y-%m-%d](%H:%M)"`${RESET}x•"
  echo -e "$OKRED GATHERING WHOIS INFO $RESET"
  echo -e "${OKGREEN}==================================================================================${RESET}•x${OKGREEN}[`date +"%Y-%m-%d](%H:%M)"`${RESET}x•"
  if [ "$WHOIS" == "1" ]; then
    if [ "$VERBOSE" == "1" ]; then
      echo -e "$OKBLUE[$RESET${OKRED}i${RESET}$OKBLUE]$OKGREEN whois $TARGET 2> /dev/null | tee $LOOT_DIR/osint/whois-$TARGET.txt 2> /dev/null $RESET"
    fi
    whois $TARGET 2> /dev/null | tee $LOOT_DIR/osint/whois-$TARGET.txt 2> /dev/null 
    if [ "$SLACK_NOTIFICATIONS_WHOIS" == "1" ]; then
      /bin/bash "$INSTALL_DIR/bin/slack.sh" postfile "$LOOT_DIR/osint/whois-$TARGET.txt"
    fi
  fi
  echo -e "${OKGREEN}==================================================================================${RESET}•x${OKGREEN}[`date +"%Y-%m-%d](%H:%M)"`${RESET}x•"
  echo -e "$OKRED GATHERING DNS INFO $RESET"
  echo -e "${OKGREEN}==================================================================================${RESET}•x${OKGREEN}[`date +"%Y-%m-%d](%H:%M)"`${RESET}x•"
  if [ "$VERBOSE" == "1" ]; then
    echo -e "$OKBLUE[$RESET${OKRED}i${RESET}$OKBLUE]$OKGREEN dig all +short $TARGET > $LOOT_DIR/nmap/dns-$TARGET.txt 2> /dev/null"
    echo -e "$OKBLUE[$RESET${OKRED}i${RESET}$OKBLUE]$OKGREEN dig all +short -x $TARGET >> $LOOT_DIR/nmap/dns-$TARGET.txt 2> /dev/null"
    echo -e "$OKBLUE[$RESET${OKRED}i${RESET}$OKBLUE]$OKGREEN dnsenum $TARGET 2> /dev/null | tee $LOOT_DIR/output/dnsenum-$TARGET.txt 2> /dev/null$RESET"
  fi
  dig all +short $TARGET > $LOOT_DIR/nmap/dns-$TARGET.txt 2> /dev/null
  dig all +short -x $TARGET >> $LOOT_DIR/nmap/dns-$TARGET.txt 2> /dev/null
  host $TARGET 2> /dev/null | grep address 2> /dev/null | awk '{print $4}' 2> /dev/null >> $LOOT_DIR/ips/ips-all-unsorted.txt 2> /dev/null
  dnsenum $TARGET 2> /dev/null | tee $LOOT_DIR/output/dnsenum-$TARGET.txt 2> /dev/null
  mv -f *_ips.txt $LOOT_DIR/domains/ 2>/dev/null

  if [ $SCAN_TYPE == "DOMAIN" ];
  then
    echo -e "${OKGREEN}==================================================================================${RESET}•x${OKGREEN}[`date +"%Y-%m-%d](%H:%M)"`${RESET}x•"
    echo -e "$OKRED CHECKING FOR SUBDOMAIN HIJACKING $RESET"
    echo -e "${OKGREEN}==================================================================================${RESET}•x${OKGREEN}[`date +"%Y-%m-%d](%H:%M)"`${RESET}x•"
    if [ "$VERBOSE" == "1" ]; then
      echo -e "$OKBLUE[$RESET${OKRED}i${RESET}$OKBLUE]$OKGREEN cat $LOOT_DIR/nmap/dns-$TARGET.txt 2> /dev/null | egrep -i \"wordpress|instapage|heroku|github|bitbucket|squarespace|fastly|feed|fresh|ghost|helpscout|helpjuice|instapage|pingdom|surveygizmo|teamwork|tictail|shopify|desk|teamwork|unbounce|helpjuice|helpscout|pingdom|tictail|campaign|monitor|cargocollective|statuspage|tumblr|amazon|hubspot|cloudfront|modulus|unbounce|uservoice|wpengine|cloudapp\" | tee $LOOT_DIR/nmap/takeovers-$TARGET.txt 2>/dev/null$RESET"
    fi
    cat $LOOT_DIR/nmap/dns-$TARGET.txt 2> /dev/null | egrep -i "wordpress|instapage|heroku|github|bitbucket|squarespace|fastly|feed|fresh|ghost|helpscout|helpjuice|instapage|pingdom|surveygizmo|teamwork|tictail|shopify|desk|teamwork|unbounce|helpjuice|helpscout|pingdom|tictail|campaign|monitor|cargocollective|statuspage|tumblr|amazon|hubspot|cloudfront|modulus|unbounce|uservoice|wpengine|cloudapp" | tee $LOOT_DIR/nmap/takeovers-$TARGET.txt 2>/dev/null

    source modes/osint.sh
    source modes/recon.sh

    cd $INSTALL_DIR
    echo ""
  fi
  echo ""
  echo -e "${OKGREEN}==================================================================================${RESET}•x${OKGREEN}[`date +"%Y-%m-%d](%H:%M)"`${RESET}x•"
  echo -e "$OKRED RUNNING TCP PORT SCAN $RESET"
  echo -e "${OKGREEN}==================================================================================${RESET}•x${OKGREEN}[`date +"%Y-%m-%d](%H:%M)"`${RESET}x•"
  if [ "$VERBOSE" == "1" ]; then
      echo -e "$OKBLUE[$RESET${OKRED}i${RESET}$OKBLUE]$OKGREEN nmap -sS --open -Pn $TARGET -oX $LOOT_DIR/nmap/nmap-$TARGET.xml | tee $LOOT_DIR/nmap/nmap-$TARGET.txt$RESET"
  fi
  nmap -sS --open -Pn $TARGET -oX $LOOT_DIR/nmap/nmap-$TARGET.xml | tee $LOOT_DIR/nmap/nmap-$TARGET.txt
  HOST_UP=$(cat $LOOT_DIR/nmap/nmap-$TARGET.txt $LOOT_DIR/nmap/nmap-$TARGET-*.txt 2> /dev/null | grep "host up" 2> /dev/null)
  if [ ${#HOST_UP} -ge 2 ]; then
    echo "$TARGET" >> $LOOT_DIR/nmap/livehosts-unsorted.txt 2> /dev/null
  fi
  sort -u $LOOT_DIR/nmap/livehosts-unsorted.txt 2> /dev/null > $LOOT_DIR/nmap/livehosts-sorted.txt 2> /dev/null
  rm -f $LOOT_DIR/nmap/ports-$TARGET.txt 2> /dev/null
  for PORT in `cat $LOOT_DIR/nmap/nmap-$TARGET.xml $LOOT_DIR/nmap/nmap-$TARGET-*.xml 2>/dev/null | egrep 'state="open"' | cut -d' ' -f3 | cut -d\" -f2 | sort -u | grep '[[:digit:]]'`; do
    echo "$PORT " >> $LOOT_DIR/nmap/ports-$TARGET.txt
  done
  if [ "$SLACK_NOTIFICATIONS_NMAP" == "1" ]; then
    /bin/bash "$INSTALL_DIR/bin/slack.sh" postfile "$LOOT_DIR/nmap/nmap-$TARGET.txt"
  fi
 
  port_80=`grep 'portid="80"' $LOOT_DIR/nmap/nmap-$TARGET.xml | grep open`
  port_443=`grep 'portid="443"' $LOOT_DIR/nmap/nmap-$TARGET.xml | grep open`
 
  if [ -z "$port_80" ];
  then
    echo -e "$OKRED + -- --=[ Port 80 closed... skipping.$RESET"
  else
    echo -e "$OKORANGE + -- --=[ Port 80 opened... running tests...$RESET"
    echo "$TARGET" >> $LOOT_DIR/web/webhosts-unsorted.txt 2> /dev/null
    echo -e "${OKGREEN}==================================================================================${RESET}•x${OKGREEN}[`date +"%Y-%m-%d](%H:%M)"`${RESET}x•"
    echo -e "$OKRED CHECKING HTTP HEADERS AND METHODS $RESET"
    echo -e "${OKGREEN}==================================================================================${RESET}•x${OKGREEN}[`date +"%Y-%m-%d](%H:%M)"`${RESET}x•"
    if [ "$VERBOSE" == "1" ]; then
      echo -e "$OKBLUE[$RESET${OKRED}i${RESET}$OKBLUE]$OKGREEN wget -qO- -T 1 --connect-timeout=3 --read-timeout=3 --tries=1 http://$TARGET |  perl -l -0777 -ne 'print $1 if /<title.*?>\s*(.*?)\s*<\/title/si' >> $LOOT_DIR/web/title-http-$TARGET.txt 2> /dev/null$RESET"
      echo -e "$OKBLUE[$RESET${OKRED}i${RESET}$OKBLUE]$OKGREEN curl --connect-timeout=5 --max-time 3 -I -s -R http://$TARGET | tee $LOOT_DIR/web/headers-http-$TARGET.txt 2> /dev/null$RESET"
    fi
    wget -qO- -T 1 --connect-timeout=5 --read-timeout=10 --tries=1 http://$TARGET |  perl -l -0777 -ne 'print $1 if /<title.*?>\s*(.*?)\s*<\/title/si' >> $LOOT_DIR/web/title-http-$TARGET.txt 2> /dev/null
    curl --connect-timeout 5 --max-time 10 -I -s -R http://$TARGET | tee $LOOT_DIR/web/headers-http-$TARGET.txt 2> /dev/null
    curl --connect-timeout 5 -s -R -L http://$TARGET > $LOOT_DIR/web/websource-http-$TARGET.txt 2> /dev/null
    curl --connect-timeout 5 --max-time 10 -I -s -R -X OPTIONS http://$TARGET | grep Allow\: | tee $LOOT_DIR/web/http_options-$TARGET-port80.txt 2> /dev/null
    echo -e "${OKGREEN}==================================================================================${RESET}•x${OKGREEN}[`date +"%Y-%m-%d](%H:%M)"`${RESET}x•"
    echo -e "$OKRED DISPLAYING META GENERATOR TAGS $RESET"
    echo -e "${OKGREEN}==================================================================================${RESET}•x${OKGREEN}[`date +"%Y-%m-%d](%H:%M)"`${RESET}x•"
    cat $LOOT_DIR/web/websource-http-$TARGET.txt 2> /dev/null | grep generator | cut -d\" -f4 2> /dev/null | tee $LOOT_DIR/web/webgenerator-http-$TARGET.txt 2> /dev/null
    echo -e "${OKGREEN}==================================================================================${RESET}•x${OKGREEN}[`date +"%Y-%m-%d](%H:%M)"`${RESET}x•"
    echo -e "$OKRED DISPLAYING COMMENTS $RESET"
    echo -e "${OKGREEN}==================================================================================${RESET}•x${OKGREEN}[`date +"%Y-%m-%d](%H:%M)"`${RESET}x•"
    cat $LOOT_DIR/web/websource-http-$TARGET.txt 2> /dev/null | grep "<\!\-\-" 2> /dev/null | tee $LOOT_DIR/web/webcomments-http-$TARGET 2> /dev/null
    sed -r "s/</\&lh\;/g" $LOOT_DIR/web/webcomments-http-$TARGET 2> /dev/null > $LOOT_DIR/web/webcomments-http-$TARGET.txt 2> /dev/null
    rm -f $LOOT_DIR/web/webcomments-http-$TARGET 2> /dev/null
    echo -e "${OKGREEN}==================================================================================${RESET}•x${OKGREEN}[`date +"%Y-%m-%d](%H:%M)"`${RESET}x•"
    echo -e "$OKRED DISPLAYING SITE LINKS $RESET"
    echo -e "${OKGREEN}==================================================================================${RESET}•x${OKGREEN}[`date +"%Y-%m-%d](%H:%M)"`${RESET}x•"
    cat $LOOT_DIR/web/websource-http-$TARGET.txt 2> /dev/null | egrep "\"" | cut -d\" -f2 | grep  \/ | sort -u 2> /dev/null | tee $LOOT_DIR/web/weblinks-http-$TARGET.txt 2> /dev/null
    if [ "$WAFWOOF" = "1" ]; then
      echo -e "${OKGREEN}==================================================================================${RESET}•x${OKGREEN}[`date +"%Y-%m-%d](%H:%M)"`${RESET}x•"
      echo -e "$OKRED CHECKING FOR WAF $RESET"
      echo -e "${OKGREEN}==================================================================================${RESET}•x${OKGREEN}[`date +"%Y-%m-%d](%H:%M)"`${RESET}x•"
      wafw00f http://$TARGET | tee $LOOT_DIR/web/waf-$TARGET-http.raw 2> /dev/null
      sed -r "s/\x1B\[([0-9]{1,2}(;[0-9]{1,2})?)?[mGK]//g" $LOOT_DIR/web/waf-$TARGET-http.raw > $LOOT_DIR/web/waf-$TARGET-http.txt 2> /dev/null
      rm -f $LOOT_DIR/web/waf-$TARGET-http.raw 2> /dev/null
      echo ""
    fi
    if [ "$WHATWEB" = "1" ]; then
      echo -e "${OKGREEN}==================================================================================${RESET}•x${OKGREEN}[`date +"%Y-%m-%d](%H:%M)"`${RESET}x•"
      echo -e "$OKRED GATHERING HTTP INFO $RESET"
      echo -e "${OKGREEN}==================================================================================${RESET}•x${OKGREEN}[`date +"%Y-%m-%d](%H:%M)"`${RESET}x•"
      whatweb -a 3 http://$TARGET | tee $LOOT_DIR/web/whatweb-$TARGET-http.raw  2> /dev/null
      sed -r "s/\x1B\[([0-9]{1,2}(;[0-9]{1,2})?)?[mGK]//g" $LOOT_DIR/web/whatweb-$TARGET-http.raw > $LOOT_DIR/web/whatweb-$TARGET-http.txt 2> /dev/null
      rm -f $LOOT_DIR/web/whatweb-$TARGET-http.raw 2> /dev/null
    fi
    if [ "$WIG" = "1" ]; then
      echo -e "${OKGREEN}==================================================================================${RESET}•x${OKGREEN}[`date +"%Y-%m-%d](%H:%M)"`${RESET}x•"
      echo -e "$OKRED GATHERING SERVER INFO $RESET"
      echo -e "${OKGREEN}==================================================================================${RESET}•x${OKGREEN}[`date +"%Y-%m-%d](%H:%M)"`${RESET}x•"
      python3 $PLUGINS_DIR/wig/wig.py -d -q http://$TARGET | tee $LOOT_DIR/web/wig-$TARGET-http
      sed -r "s/\x1B\[([0-9]{1,2}(;[0-9]{1,2})?)?[mGK]//g" $LOOT_DIR/web/wig-$TARGET-http > $LOOT_DIR/web/wig-$TARGET-http.txt 2> /dev/null
    fi
    if [ "$WEBTECH" = "1" ]; then
      echo -e "${OKGREEN}==================================================================================${RESET}•x${OKGREEN}[`date +"%Y-%m-%d](%H:%M)"`${RESET}x•"
      echo -e "$OKRED GATHERING WEB FINGERPRINT $RESET"
      echo -e "${OKGREEN}==================================================================================${RESET}•x${OKGREEN}[`date +"%Y-%m-%d](%H:%M)"`${RESET}x•"
      webtech -u http://$TARGET | grep \- | cut -d- -f2- | tee $LOOT_DIR/web/webtech-$TARGET-http.txt
    fi
    if [ "$PASSIVE_SPIDER" == "1" ]; then
      echo -e "${OKGREEN}==================================================================================${RESET}•x${OKGREEN}[`date +"%Y-%m-%d](%H:%M)"`${RESET}x•"
      echo -e "$OKRED RUNNING PASSIVE WEB SPIDER $RESET"
      echo -e "${OKGREEN}==================================================================================${RESET}•x${OKGREEN}[`date +"%Y-%m-%d](%H:%M)"`${RESET}x•"
      if [ "$VERBOSE" == "1" ]; then
        echo -e "$OKBLUE[$RESET${OKRED}i${RESET}$OKBLUE]$OKGREEN curl -sX GET "http://index.commoncrawl.org/CC-MAIN-2018-22-index?url=*.$TARGET&output=json" | jq -r .url | tee $LOOT_DIR/web/passivespider-$TARGET.txt 2> /dev/null$RESET"
      fi
      curl -sX GET "http://index.commoncrawl.org/CC-MAIN-2018-22-index?url=*.$TARGET&output=json" | jq -r .url | tee $LOOT_DIR/web/passivespider-$TARGET.txt 2> /dev/null
    fi
    if [ "$WAYBACKMACHINE" == "1" ]; then
      echo -e "${OKGREEN}==================================================================================${RESET}•x${OKGREEN}[`date +"%Y-%m-%d](%H:%M)"`${RESET}x•"
      echo -e "$OKRED FETCHING WAYBACK MACHINE URLS $RESET"
      echo -e "${OKGREEN}==================================================================================${RESET}•x${OKGREEN}[`date +"%Y-%m-%d](%H:%M)"`${RESET}x•"
      if [ "$VERBOSE" == "1" ]; then
        echo -e "$OKBLUE[$RESET${OKRED}i${RESET}$OKBLUE]$OKGREEN curl -sX GET "http://web.archive.org/cdx/search/cdx?url=*.$TARGET/*&output=text&fl=original&collapse=urlkey" | tee $LOOT_DIR/web/waybackurls-$TARGET.txt 2> /dev/null$RESET"
      fi
      curl -sX GET "http://web.archive.org/cdx/search/cdx?url=*.$TARGET/*&output=text&fl=original&collapse=urlkey" | tee $LOOT_DIR/web/waybackurls-$TARGET.txt 2> /dev/null
    fi
    if [ "$BLACKWIDOW" == "1" ]; then
      echo -e "${OKGREEN}==================================================================================${RESET}•x${OKGREEN}[`date +"%Y-%m-%d](%H:%M)"`${RESET}x•"
      echo -e "$OKRED RUNNING ACTIVE WEB SPIDER $RESET"
      echo -e "${OKGREEN}==================================================================================${RESET}•x${OKGREEN}[`date +"%Y-%m-%d](%H:%M)"`${RESET}x•"
      if [ "$VERBOSE" == "1" ]; then
        echo -e "$OKBLUE[$RESET${OKRED}i${RESET}$OKBLUE]$OKGREEN blackwidow -u http://$TARGET:80 -l 2 $RESET"
      fi
      touch $LOOT_DIR/web/spider-$TARGET.txt 2>/dev/null
      cp $LOOT_DIR/web/spider-$TARGET.txt $LOOT_DIR/web/spider-$TARGET.bak 2>/dev/null
      blackwidow -u http://$TARGET:80 -l 2 -v n
      cat /usr/share/blackwidow/$TARGET*/* > $LOOT_DIR/web/spider-$TARGET.txt 2>/dev/null
      cat $LOOT_DIR/web/waybackurls-$TARGET.txt 2> /dev/null >> $LOOT_DIR/web/spider-$TARGET.txt 2>/dev/null
      cat $LOOT_DIR/web/passivespider-$TARGET.txt 2> /dev/null >> $LOOT_DIR/web/spider-$TARGET.txt 2>/dev/null
      sed -ir "s/</\&lh\;/g" $LOOT_DIR/web/spider-$TARGET.txt 2>/dev/null
      sort -u $LOOT_DIR/web/spider-$TARGET.txt 2>/dev/null > $LOOT_DIR/web/spider-$TARGET.sorted 2>/dev/null
      mv $LOOT_DIR/web/spider-$TARGET.sorted $LOOT_DIR/web/spider-$TARGET.txt 2>/dev/null
      diff $LOOT_DIR/web/spider-$TARGET.bak $LOOT_DIR/web/spider-$TARGET.txt 2> /dev/null | grep "> " 2> /dev/null | awk '{print $2}' 2> /dev/null > $LOOT_DIR/web/spider-new-$TARGET.txt
      if [ "$SLACK_NOTIFICATIONS_SPIDER_NEW" == "1" ]; then
        /bin/bash "$INSTALL_DIR/bin/slack.sh" postfile "$LOOT_DIR/web/spider-new-$TARGET.txt"
      fi
    fi
    if [ "$WEB_BRUTE_STEALTHSCAN" == "1" ]; then
      echo -e "${OKGREEN}==================================================================================${RESET}•x${OKGREEN}[`date +"%Y-%m-%d](%H:%M)"`${RESET}x•"
      echo -e "$OKRED RUNNING FILE/DIRECTORY BRUTE FORCE $RESET"
      echo -e "${OKGREEN}==================================================================================${RESET}•x${OKGREEN}[`date +"%Y-%m-%d](%H:%M)"`${RESET}x•"
      if [ "$VERBOSE" == "1" ]; then
        echo -e "$OKBLUE[$RESET${OKRED}i${RESET}$OKBLUE]$OKGREEN python3 $PLUGINS_DIR/dirsearch/dirsearch.py -u http://$TARGET -w $WEB_BRUTE_STEALTH -x 400,403,404,405,406,429,502,503,504 -F -e php,asp,aspx,bak,zip,tar.gz,html,htm $RESET"
      fi
      if [ "$DIRSEARCH" == "1" ]; then
        touch $LOOT_DIR/web/dirsearch-$TARGET.bak 2> /dev/null
        cp $LOOT_DIR/web/dirsearch-$TARGET.txt $LOOT_DIR/web/dirsearch-$TARGET.bak 2> /dev/null
        python3 $PLUGINS_DIR/dirsearch/dirsearch.py -u http://$TARGET -w $WEB_BRUTE_STEALTH -x 400,403,404,405,406,429,502,503,504 -F -e * -t $THREADS --random-agents --plain-text-report=$LOOT_DIR/web/dirsearch-$TARGET.txt 2> /dev/null > /dev/null && cat $LOOT_DIR/web/dirsearch-$TARGET.txt
        cat $PLUGINS_DIR/dirsearch/reports/$TARGET/* 2> /dev/null
        cat $PLUGINS_DIR/dirsearch/reports/$TARGET/* > $LOOT_DIR/web/dirsearch-$TARGET.txt 2> /dev/null
        sort -u $LOOT_DIR/web/dirsearch-$TARGET.txt 2> /dev/null > $LOOT_DIR/web/dirsearch-$TARGET.sorted 2> /dev/null
        mv $LOOT_DIR/web/dirsearch-$TARGET.sorted $LOOT_DIR/web/dirsearch-$TARGET.txt 2> /dev/null 
        diff $LOOT_DIR/web/dirsearch-$TARGET.bak $LOOT_DIR/web/dirsearch-$TARGET.txt 2> /dev/null | grep "> " 2> /dev/null | awk '{print $2 " " $3 " " $4}' 2> /dev/null > $LOOT_DIR/web/dirsearch-new-$TARGET.txt
        if [ "$SLACK_NOTIFICATIONS_DIRSEARCH_NEW" == "1" ]; then
          /bin/bash "$INSTALL_DIR/bin/slack.sh" postfile "$LOOT_DIR/web/dirsearch-new-$TARGET.txt"
        fi
      fi
      if [ "$GOBUSTER" == "1" ]; then
        gobuster -u http://$TARGET -w $WEB_BRUTE_STEALTH -e | tee $LOOT_DIR/web/webbrute-$TARGET-http-stealth.txt
        sort -u $LOOT_DIR/web/webbrute-$TARGET-*.txt 2> /dev/null > $LOOT_DIR/web/webbrute-$TARGET.txt 2> /dev/null
      fi
      wget http://$TARGET/robots.txt -O $LOOT_DIR/web/robots-$TARGET-http.txt 2> /dev/null
    fi
    echo -e "${OKGREEN}==================================================================================${RESET}•x${OKGREEN}[`date +"%Y-%m-%d](%H:%M)"`${RESET}x•"
    echo -e "$OKRED SAVING SCREENSHOTS $RESET"
    echo -e "${OKGREEN}==================================================================================${RESET}•x${OKGREEN}[`date +"%Y-%m-%d](%H:%M)"`${RESET}x•"
    if [ $CUTYCAPT = "1" ]; then
      if [ ${DISTRO} == "blackarch"  ]; then
        /bin/CutyCapt --url=http://$TARGET --out=$LOOT_DIR/screenshots/$TARGET-port80.jpg --insecure --max-wait=5000 2> /dev/null
      else
        if [ "$VERBOSE" == "1" ]; then
          echo -e "$OKBLUE[$RESET${OKRED}i${RESET}$OKBLUE]$OKGREEN cutycapt --url=http://$TARGET --out=$LOOT_DIR/screenshots/$TARGET-port80.jpg --insecure --max-wait=5000 2> /dev/null$RESET"
        fi
        cutycapt --url=http://$TARGET --out=$LOOT_DIR/screenshots/$TARGET-port80.jpg --insecure --max-wait=5000 2> /dev/null
      fi
    fi
    if [ $WEBSCREENSHOT = "1" ]; then
      cd $LOOT_DIR
      python2 $INSTALL_DIR/bin/webscreenshot.py -t 5 http://$TARGET:80
    fi
  fi
 
  if [ -z "$port_443" ];
  then
    echo -e "$OKRED + -- --=[ Port 443 closed... skipping.$RESET"
  else
    echo -e "$OKORANGE + -- --=[ Port 443 opened... running tests...$RESET"
    echo "$TARGET" >> $LOOT_DIR/web/webhosts-unsorted.txt 2> /dev/null
    echo -e "${OKGREEN}==================================================================================${RESET}•x${OKGREEN}[`date +"%Y-%m-%d](%H:%M)"`${RESET}x•"
    echo -e "$OKRED CHECKING HTTP HEADERS AND METHODS $RESET"
    echo -e "${OKGREEN}==================================================================================${RESET}•x${OKGREEN}[`date +"%Y-%m-%d](%H:%M)"`${RESET}x•"
    if [ "$VERBOSE" == "1" ]; then
      echo -e "$OKBLUE[$RESET${OKRED}i${RESET}$OKBLUE]$OKGREEN wget -qO- -T 1 --connect-timeout=3 --read-timeout=3 --tries=1 https://$TARGET |  perl -l -0777 -ne 'print $1 if /<title.*?>\s*(.*?)\s*<\/title/si' >> $LOOT_DIR/web/title-https-$TARGET.txt 2> /dev/null$RESET"
      echo -e "$OKBLUE[$RESET${OKRED}i${RESET}$OKBLUE]$OKGREEN curl --connect-timeout=5 --max-time 3 -I -s -R https://$TARGET | tee $LOOT_DIR/web/headers-https-$TARGET.txt 2> /dev/null$RESET"
    fi
    wget -qO- -T 1 --connect-timeout=5 --read-timeout=10 --tries=1 https://$TARGET |  perl -l -0777 -ne 'print $1 if /<title.*?>\s*(.*?)\s*<\/title/si' >> $LOOT_DIR/web/title-https-$TARGET.txt 2> /dev/null
    curl --connect-timeout 5 --max-time 10 -I -s -R https://$TARGET | tee $LOOT_DIR/web/headers-https-$TARGET.txt 2> /dev/null
    curl --connect-timeout 5 -s -R -L https://$TARGET > $LOOT_DIR/web/websource-https-$TARGET.txt 2> /dev/null
    curl --connect-timeout 5 --max-time 10 -I -s -R -X OPTIONS https://$TARGET | grep Allow\: | tee $LOOT_DIR/web/http_options-$TARGET-port443.txt 2> /dev/null
    echo -e "${OKGREEN}==================================================================================${RESET}•x${OKGREEN}[`date +"%Y-%m-%d](%H:%M)"`${RESET}x•"
    echo -e "$OKRED DISPLAYING META GENERATOR TAGS $RESET"
    echo -e "${OKGREEN}==================================================================================${RESET}•x${OKGREEN}[`date +"%Y-%m-%d](%H:%M)"`${RESET}x•"
    cat $LOOT_DIR/web/websource-https-$TARGET.txt 2> /dev/null | grep generator | cut -d\" -f4 2> /dev/null | tee $LOOT_DIR/web/webgenerator-https-$TARGET.txt 2> /dev/null
    echo -e "${OKGREEN}==================================================================================${RESET}•x${OKGREEN}[`date +"%Y-%m-%d](%H:%M)"`${RESET}x•"
    echo -e "$OKRED DISPLAYING COMMENTS $RESET"
    echo -e "${OKGREEN}==================================================================================${RESET}•x${OKGREEN}[`date +"%Y-%m-%d](%H:%M)"`${RESET}x•"
    cat $LOOT_DIR/web/websource-https-$TARGET.txt 2> /dev/null | grep "<\!\-\-" 2> /dev/null | tee $LOOT_DIR/web/webcomments-https-$TARGET 2> /dev/null
    sed -r "s/</\&lh\;/g" $LOOT_DIR/web/webcomments-https-$TARGET 2> /dev/null > $LOOT_DIR/web/webcomments-https-$TARGET.txt 2> /dev/null
    rm -f $LOOT_DIR/web/webcomments-https-$TARGET 2> /dev/null
    echo -e "${OKGREEN}==================================================================================${RESET}•x${OKGREEN}[`date +"%Y-%m-%d](%H:%M)"`${RESET}x•"
    echo -e "$OKRED DISPLAYING SITE LINKS $RESET"
    echo -e "${OKGREEN}==================================================================================${RESET}•x${OKGREEN}[`date +"%Y-%m-%d](%H:%M)"`${RESET}x•"
    cat $LOOT_DIR/web/websource-https-$TARGET.txt 2> /dev/null | egrep "\"" | cut -d\" -f2 | grep  \/ | sort -u 2> /dev/null | tee $LOOT_DIR/web/weblinks-https-$TARGET.txt 2> /dev/null
    if [ "$WAFWOOF" = "1" ]; then
      echo -e "${OKGREEN}==================================================================================${RESET}•x${OKGREEN}[`date +"%Y-%m-%d](%H:%M)"`${RESET}x•"
      echo -e "$OKRED CHECKING FOR WAF $RESET"
      echo -e "${OKGREEN}==================================================================================${RESET}•x${OKGREEN}[`date +"%Y-%m-%d](%H:%M)"`${RESET}x•"
      wafw00f https://$TARGET | tee $LOOT_DIR/web/waf-$TARGET-https.raw 2> /dev/null
      sed -r "s/\x1B\[([0-9]{1,2}(;[0-9]{1,2})?)?[mGK]//g" $LOOT_DIR/web/waf-$TARGET-https.raw > $LOOT_DIR/web/waf-$TARGET-https.txt 2> /dev/null
      rm -f $LOOT_DIR/web/waf-$TARGET-https.raw 2> /dev/null
      echo ""
    fi
    if [ "$WHATWEB" = "1" ]; then
      echo -e "${OKGREEN}==================================================================================${RESET}•x${OKGREEN}[`date +"%Y-%m-%d](%H:%M)"`${RESET}x•"
      echo -e "$OKRED GATHERING HTTP INFO $RESET"
      echo -e "${OKGREEN}==================================================================================${RESET}•x${OKGREEN}[`date +"%Y-%m-%d](%H:%M)"`${RESET}x•"
      whatweb -a 3 https://$TARGET | tee $LOOT_DIR/web/whatweb-$TARGET-https.raw  2> /dev/null
      sed -r "s/\x1B\[([0-9]{1,2}(;[0-9]{1,2})?)?[mGK]//g" $LOOT_DIR/web/whatweb-$TARGET-https.raw > $LOOT_DIR/web/whatweb-$TARGET-https.txt 2> /dev/null
      rm -f $LOOT_DIR/web/whatweb-$TARGET-https.raw 2> /dev/null
    fi
    if [ "$WIG" = "1" ]; then
      echo -e "${OKGREEN}==================================================================================${RESET}•x${OKGREEN}[`date +"%Y-%m-%d](%H:%M)"`${RESET}x•"
      echo -e "$OKRED GATHERING SERVER INFO $RESET"
      echo -e "${OKGREEN}==================================================================================${RESET}•x${OKGREEN}[`date +"%Y-%m-%d](%H:%M)"`${RESET}x•"
      python3 $PLUGINS_DIR/wig/wig.py -d -q https://$TARGET | tee $LOOT_DIR/web/wig-$TARGET-https
      sed -r "s/\x1B\[([0-9]{1,2}(;[0-9]{1,2})?)?[mGK]//g" $LOOT_DIR/web/wig-$TARGET-https > $LOOT_DIR/web/wig-$TARGET-https.txt 2> /dev/null
    fi
    if [ "$WEBTECH" = "1" ]; then
      echo -e "${OKGREEN}==================================================================================${RESET}•x${OKGREEN}[`date +"%Y-%m-%d](%H:%M)"`${RESET}x•"
      echo -e "$OKRED GATHERING WEB FINGERPRINT $RESET"
      echo -e "${OKGREEN}==================================================================================${RESET}•x${OKGREEN}[`date +"%Y-%m-%d](%H:%M)"`${RESET}x•"
      webtech -u https://$TARGET | grep \- | cut -d- -f2- | tee $LOOT_DIR/web/webtech-$TARGET-https.txt
    fi
    if [ "$PASSIVE_SPIDER" = "1" ]; then
      echo -e "${OKGREEN}==================================================================================${RESET}•x${OKGREEN}[`date +"%Y-%m-%d](%H:%M)"`${RESET}x•"
      echo -e "$OKRED RUNNING PASSIVE WEB SPIDER $RESET"
      echo -e "${OKGREEN}==================================================================================${RESET}•x${OKGREEN}[`date +"%Y-%m-%d](%H:%M)"`${RESET}x•"
      if [ "$VERBOSE" == "1" ]; then
        echo -e "$OKBLUE[$RESET${OKRED}i${RESET}$OKBLUE]$OKGREEN curl -sX GET "http://index.commoncrawl.org/CC-MAIN-2018-22-index?url=*.$TARGET&output=json" | jq -r .url | tee $LOOT_DIR/web/spider-$TARGET.txt 2> /dev/null$RESET"
      fi
      curl -sX GET "http://index.commoncrawl.org/CC-MAIN-2018-22-index?url=*.$TARGET&output=json" | jq -r .url | tee $LOOT_DIR/web/passivespider-$TARGET.txt 2> /dev/null
    fi
    if [ "$BLACKWIDOW" == "1" ]; then
      echo -e "${OKGREEN}==================================================================================${RESET}•x${OKGREEN}[`date +"%Y-%m-%d](%H:%M)"`${RESET}x•"
      echo -e "$OKRED RUNNING ACTIVE WEB SPIDER $RESET"
      echo -e "${OKGREEN}==================================================================================${RESET}•x${OKGREEN}[`date +"%Y-%m-%d](%H:%M)"`${RESET}x•"
      if [ "$VERBOSE" == "1" ]; then
        echo -e "$OKBLUE[$RESET${OKRED}i${RESET}$OKBLUE]$OKGREEN blackwidow -u https://$TARGET:443 -l 3$RESET"
      fi
      touch $LOOT_DIR/web/spider-$TARGET.txt 2>/dev/null
      cp $LOOT_DIR/web/spider-$TARGET.txt $LOOT_DIR/web/spider-$TARGET.bak 2>/dev/null
      blackwidow -u https://$TARGET:443 -l 2 -v n
      cat /usr/share/blackwidow/$TARGET*/* > $LOOT_DIR/web/spider-$TARGET.txt 2>/dev/null
      cat $LOOT_DIR/web/waybackurls-$TARGET.txt 2> /dev/null >> $LOOT_DIR/web/spider-$TARGET.txt 2>/dev/null
      cat $LOOT_DIR/web/passivespider-$TARGET.txt 2> /dev/null >> $LOOT_DIR/web/spider-$TARGET.txt 2>/dev/null
      sed -ir "s/</\&lh\;/g" $LOOT_DIR/web/spider-$TARGET.txt 2>/dev/null
      sort -u $LOOT_DIR/web/spider-$TARGET.txt 2>/dev/null > $LOOT_DIR/web/spider-$TARGET.sorted 2>/dev/null
      mv $LOOT_DIR/web/spider-$TARGET.sorted $LOOT_DIR/web/spider-$TARGET.txt 2>/dev/null
      diff $LOOT_DIR/web/spider-$TARGET.bak $LOOT_DIR/web/spider-$TARGET.txt 2> /dev/null | grep "> " 2> /dev/null | awk '{print $2}' 2> /dev/null > $LOOT_DIR/web/spider-new-$TARGET.txt
      if [ "$SLACK_NOTIFICATIONS_SPIDER_NEW" == "1" ]; then
        /bin/bash "$INSTALL_DIR/bin/slack.sh" postfile "$LOOT_DIR/web/spider-new-$TARGET.txt"
      fi
    fi
    if [ $WEB_BRUTE_STEALTHSCAN == "1" ]; then
      echo -e "${OKGREEN}==================================================================================${RESET}•x${OKGREEN}[`date +"%Y-%m-%d](%H:%M)"`${RESET}x•"
      echo -e "$OKRED RUNNING FILE/DIRECTORY BRUTE FORCE $RESET"
      echo -e "${OKGREEN}==================================================================================${RESET}•x${OKGREEN}[`date +"%Y-%m-%d](%H:%M)"`${RESET}x•"
      if [ "$VERBOSE" == "1" ]; then
        echo -e "$OKBLUE[$RESET${OKRED}i${RESET}$OKBLUE]$OKGREEN python3 $PLUGINS_DIR/dirsearch/dirsearch.py -u https://$TARGET -w $WEB_BRUTE_STEALTH -x 400,403,404,405,406,429,502,503,504 -F -e php,asp,aspx,bak,zip,tar.gz,html,htm $RESET"
      fi
      if [ "$DIRSEARCH" == "1" ]; then
        touch $LOOT_DIR/web/dirsearch-$TARGET.bak 2> /dev/null
        cp $LOOT_DIR/web/dirsearch-$TARGET.txt $LOOT_DIR/web/dirsearch-$TARGET.bak 2> /dev/null
        python3 $PLUGINS_DIR/dirsearch/dirsearch.py -u https://$TARGET -w $WEB_BRUTE_STEALTH -x 400,403,404,405,406,429,502,503,504 -F -e * -t $THREADS --random-agents --plain-text-report=$LOOT_DIR/web/dirsearch-$TARGET.txt 2> /dev/null > /dev/null && cat $LOOT_DIR/web/dirsearch-$TARGET.txt
        cat $PLUGINS_DIR/dirsearch/reports/$TARGET/* 2> /dev/null
        cat $PLUGINS_DIR/dirsearch/reports/$TARGET/* > $LOOT_DIR/web/dirsearch-$TARGET.txt 2> /dev/null
        sort -u $LOOT_DIR/web/dirsearch-$TARGET.txt 2> /dev/null > $LOOT_DIR/web/dirsearch-$TARGET.sorted 2> /dev/null
        mv $LOOT_DIR/web/dirsearch-$TARGET.sorted $LOOT_DIR/web/dirsearch-$TARGET.txt 2> /dev/null 
        diff $LOOT_DIR/web/dirsearch-$TARGET.bak $LOOT_DIR/web/dirsearch-$TARGET.txt 2> /dev/null | grep "> " 2> /dev/null | awk '{print $2 " " $3 " " $4}' 2> /dev/null > $LOOT_DIR/web/dirsearch-new-$TARGET.txt
        if [ "$SLACK_NOTIFICATIONS_DIRSEARCH_NEW" == "1" ]; then
          /bin/bash "$INSTALL_DIR/bin/slack.sh" postfile "$LOOT_DIR/web/dirsearch-new-$TARGET.txt"
        fi
      fi
      if [ "$GOBUSTER" == "1" ]; then
        gobuster -u https://$TARGET -w $WEB_BRUTE_STEALTH -e | tee $LOOT_DIR/web/webbrute-$TARGET-https-stealth.txt
        sort -u $LOOT_DIR/web/webbrute-$TARGET-*.txt 2> /dev/null > $LOOT_DIR/web/webbrute-$TARGET.txt 2> /dev/null
      fi
      if [ "$VERBOSE" == "1" ]; then
        echo -e "$OKBLUE[$RESET${OKRED}i${RESET}$OKBLUE]$OKGREEN wget https://$TARGET/robots.txt -O $LOOT_DIR/web/robots-$TARGET-https.txt 2> /dev/null$RESET"
      fi
      wget https://$TARGET/robots.txt -O $LOOT_DIR/web/robots-$TARGET-https.txt 2> /dev/null
    fi
    if [ "$SSL" = "1" ]; then
      echo -e "${OKGREEN}==================================================================================${RESET}•x${OKGREEN}[`date +"%Y-%m-%d](%H:%M)"`${RESET}x•"
      echo -e "$OKRED GATHERING SSL/TLS INFO $RESET"
      echo -e "${OKGREEN}==================================================================================${RESET}•x${OKGREEN}[`date +"%Y-%m-%d](%H:%M)"`${RESET}x•"
      if [ "$VERBOSE" == "1" ]; then
        echo -e "$OKBLUE[$RESET${OKRED}i${RESET}$OKBLUE]$OKGREEN sslscan --no-failed $TARGET | tee $LOOT_DIR/web/sslscan-$TARGET.raw 2> /dev/null$RESET"
      fi
      sslscan --no-failed $TARGET | tee $LOOT_DIR/web/sslscan-$TARGET.raw 2> /dev/null
      sed -r "s/\x1B\[([0-9]{1,2}(;[0-9]{1,2})?)?[mGK]//g" $LOOT_DIR/web/sslscan-$TARGET.raw > $LOOT_DIR/web/sslscan-$TARGET.txt 2> /dev/null
      rm -f $LOOT_DIR/web/sslscan-$TARGET.raw 2> /dev/null
    fi
    echo -e "${OKGREEN}==================================================================================${RESET}•x${OKGREEN}[`date +"%Y-%m-%d](%H:%M)"`${RESET}x•"
    echo -e "$OKRED SAVING SCREENSHOTS $RESET"
    echo -e "${OKGREEN}==================================================================================${RESET}•x${OKGREEN}[`date +"%Y-%m-%d](%H:%M)"`${RESET}x•"
    if [ $CUTYCAPT = "1" ]; then
      if [ ${DISTRO} == "blackarch"  ]; then
        /bin/CutyCapt --url=https://$TARGET --out=$LOOT_DIR/screenshots/$TARGET-port443.jpg --insecure --max-wait=5000 2> /dev/null
      else
        if [ "$VERBOSE" == "1" ]; then
          echo -e "$OKBLUE[$RESET${OKRED}i${RESET}$OKBLUE]$OKGREEN cutycapt --url=https://$TARGET --out=$LOOT_DIR/screenshots/$TARGET-port443.jpg --insecure --max-wait=5000 2> /dev/null$RESET"
        fi
        cutycapt --url=https://$TARGET --out=$LOOT_DIR/screenshots/$TARGET-port443.jpg --insecure --max-wait=5000 2> /dev/null
      fi
    fi
    if [ $WEBSCREENSHOT = "1" ]; then
      cd $LOOT_DIR
      python2 $INSTALL_DIR/bin/webscreenshot.py -t 5 https://$TARGET:443
    fi
    echo -e "$OKRED[+]$RESET Screenshot saved to $LOOT_DIR/screenshots/$TARGET-port443.jpg"
  fi
  echo -e "${OKGREEN}==================================================================================${RESET}•x${OKGREEN}[`date +"%Y-%m-%d](%H:%M)"`${RESET}x•"
  echo -e "$OKRED SCAN COMPLETE! $RESET"
  echo -e "${OKGREEN}==================================================================================${RESET}•x${OKGREEN}[`date +"%Y-%m-%d](%H:%M)"`${RESET}x•"
  echo -e ""
  echo -e ""
  echo -e ""
  echo -e ""
  echo -e ""
  echo -e ""
  echo -e ""
  echo -e ""
  echo -e ""
  echo -e ""
  echo -e ""
  echo -e ""
  echo -e ""
  echo -e ""
  echo -e ""
  echo "$TARGET" >> $LOOT_DIR/scans/updated.txt
  mv $LOOT_DIR/scans/running-$TARGET-stealth.txt $LOOT_DIR/scans/finished-$TARGET-stealth.txt 2> /dev/null
  rm -f $INSTALL_DIR/.fuse_* 2> /dev/null
  sort -u $LOOT_DIR/ips/ips-all-unsorted.txt 2> /dev/null > $LOOT_DIR/ips/ips-all-sorted.txt 2> /dev/null
  if [ "$LOOT" = "1" ]; then
    loot
  fi
  if [ "$SLACK_NOTIFICATIONS" == "1" ]; then
    /bin/bash "$INSTALL_DIR/bin/slack.sh" "[xerosecurity.com] •?((¯°·._.• Finished Sn1per scan: $TARGET [$MODE] (`date +"%Y-%m-%d %H:%M"`) •._.·°¯))؟•"
  fi
  exit
fi