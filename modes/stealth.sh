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
    if [ "$GOOHAK" = "1" ]; then
      args="$args -g"
    fi
    if [ "$RECON" = "1" ]; then
      args="$args -re"
    fi
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
    args="$args --noreport -m stealth"
    echo "sniper -t $TARGET -m $MODE --noreport $args" >> $LOOT_DIR/scans/$TARGET-$MODE.txt
    sniper $args | tee $LOOT_DIR/output/sniper-$TARGET-$MODE-`date +%Y%m%d%H%M`.txt 2>&1
    exit
  fi
  echo -e "$OKRED                ____               $RESET"
  echo -e "$OKRED    _________  /  _/___  ___  _____$RESET"
  echo -e "$OKRED   / ___/ __ \ / // __ \/ _ \/ ___/$RESET"
  echo -e "$OKRED  (__  ) / / // // /_/ /  __/ /    $RESET"
  echo -e "$OKRED /____/_/ /_/___/ .___/\___/_/     $RESET"
  echo -e "$OKRED               /_/                 $RESET"
  echo -e "$RESET"
  echo -e "$OKORANGE + -- --=[http://xerosecurity.com"
  echo -e "$OKORANGE + -- --=[sniper v$VER by 1N3"
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
  echo -e "$OKORANGE + -- --=[Launching stealth scan: $TARGET $RESET"
  echo -e "$OKGREEN $RESET"
  
  echo "$TARGET" >> $LOOT_DIR/domains/targets.txt

  echo -e "${OKGREEN}====================================================================================${RESET}"
  echo -e "$OKRED GATHERING DNS INFO $RESET"
  echo -e "${OKGREEN}====================================================================================${RESET}"
  dig all +short $TARGET > $LOOT_DIR/nmap/dns-$TARGET.txt 2> /dev/null
  dig all +short -x $TARGET >> $LOOT_DIR/nmap/dns-$TARGET.txt 2> /dev/null
  dnsenum $TARGET 2> /dev/null
  mv -f *_ips.txt $LOOT_DIR/domains/ 2>/dev/null

  if [ $SCAN_TYPE == "DOMAIN" ];
  then
    if [ "$OSINT" = "1" ]; then
      echo -e "${OKGREEN}====================================================================================${RESET}"
      echo -e "$OKRED GATHERING OSINT INFO $RESET"
      echo -e "${OKGREEN}====================================================================================${RESET}"
      theharvester -d $TARGET -l 25 -b all 2> /dev/null
      metagoofil -d $TARGET -t doc,pdf,xls,csv,txt -l 25 -n 25 -o $LOOT_DIR/osint/ -f $LOOT_DIR/osint/$TARGET.html
    fi
    
    if [ "$RECON" = "1" ]; then
      echo -e "${OKGREEN}====================================================================================${RESET}"
      echo -e "$OKRED GATHERING WHOIS INFO $RESET"
      echo -e "${OKGREEN}====================================================================================${RESET}"
      whois $TARGET
      echo -e "${OKGREEN}====================================================================================${RESET}"
      echo -e "$OKRED GATHERING DNS SUBDOMAINS VIA SUBLIST3R $RESET"
      echo -e "${OKGREEN}====================================================================================${RESET}"
      if [ "$SUBLIST3R" = "1" ]; then
        python $PLUGINS_DIR/Sublist3r/sublist3r.py -d $TARGET -vvv -o $LOOT_DIR/domains/domains-$TARGET.txt 2>/dev/null
      fi
      if [ "$AMASS" = "1" ]; then
        echo -e "${OKGREEN}====================================================================================${RESET}"
        echo -e "$OKRED GATHERING DNS SUBDOMAINS VIA AMASS $RESET"
        echo -e "${OKGREEN}====================================================================================${RESET}"
        amass -whois -ip -brute -o $LOOT_DIR/domains/domains-$TARGET-amass.txt -min-for-recursive 3 -d $TARGET 2>/dev/null
        cut -d, -f1 $LOOT_DIR/domains/domains-$TARGET-amass.txt | grep $TARGET > $LOOT_DIR/domains/domains-$TARGET-amass-sorted.txt
        cut -d, -f2 $LOOT_DIR/domains/domains-$TARGET-amass.txt > $LOOT_DIR/domains/domains-$TARGET-amass-ips-sorted.txt
      fi
      if [ "$SUBFINDER" = "1" ]; then
        echo -e "${OKGREEN}====================================================================================${RESET}"
        echo -e "$OKRED GATHERING DNS SUBDOMAINS VIA SUBFINDER $RESET"
        echo -e "${OKGREEN}====================================================================================${RESET}"
        subfinder -o $LOOT_DIR/domains/domains-$TARGET-subfinder.txt -b -d $TARGET 2>/dev/null
      fi
      echo -e "${OKGREEN}====================================================================================${RESET}"
      echo -e "$OKRED BRUTE FORCING DNS SUBDOMAINS VIA DNSCAN (THIS COULD TAKE A WHILE...) $RESET"
      echo -e "${OKGREEN}====================================================================================${RESET}"
      if [ "$DNSCAN" = "1" ]; then
        python /pentest/recon/dnscan/dnscan.py -d $TARGET -w $DOMAINS_FULL -o $LOOT_DIR/domains/domains-dnscan-$TARGET.txt -i $LOOT_DIR/domains/domains-ips-$TARGET.txt
        cat $LOOT_DIR/domains/domains-dnscan-$TARGET.txt | grep $TARGET| awk '{print $3}' | sort -u >> $LOOT_DIR/domains/domains-$TARGET.txt 2> /dev/null
        dos2unix $LOOT_DIR/domains/domains-$TARGET.txt 2>/dev/null
      fi
      echo ""
      if [ "$CRTSH" = "1" ]; then
        echo -e "$OKRED ╔═╗╦═╗╔╦╗╔═╗╦ ╦$RESET"
        echo -e "$OKRED ║  ╠╦╝ ║ ╚═╗╠═╣$RESET"
        echo -e "$OKRED ╚═╝╩╚═ ╩o╚═╝╩ ╩$RESET"
        echo -e "${OKGREEN}====================================================================================${RESET}"
        echo -e "$OKRED GATHERING CERTIFICATE SUBDOMAINS $RESET"
        echo -e "${OKGREEN}====================================================================================${RESET}"
        echo -e "$OKBLUE"
        curl -s https://crt.sh/?q=%25.$TARGET > /tmp/curl.out && cat /tmp/curl.out | grep $TARGET | grep TD | sed -e 's/<//g' | sed -e 's/>//g' | sed -e 's/TD//g' | sed -e 's/\///g' | sed -e 's/ //g' | sed -n '1!p' | sort -u > $LOOT_DIR/domains/domains-$TARGET-crt.txt && cat $LOOT_DIR/domains/domains-$TARGET-crt.txt
        echo ""
        echo -e "${OKRED}[+] Domains saved to: $LOOT_DIR/domains/domains-$TARGET-full.txt"
      fi
      cat $LOOT_DIR/domains/domains-$TARGET-crt.txt > /tmp/curl.out 2> /dev/null
      cat $LOOT_DIR/domains/domains-$TARGET.txt >> /tmp/curl.out 2> /dev/null
      cat $LOOT_DIR/domains/domains-$TARGET-amass-sorted.txt >> /tmp/curl.out 2> /dev/null
      cat $LOOT_DIR/domains/domains-$TARGET-subfinder.txt >> /tmp/curl.out 2> /dev/null
      cat $LOOT_DIR/domains/targets.txt >> /tmp/curl.out 2> /dev/null
      sort -u /tmp/curl.out > $LOOT_DIR/domains/domains-$TARGET-full.txt
      rm -f /tmp/curl.out 2> /dev/null
      echo -e "$RESET"
      echo -e "${OKGREEN}====================================================================================${RESET}"
      echo -e "$OKRED CHECKING FOR EMAIL SECURITY $RESET"
      echo -e "${OKGREEN}====================================================================================${RESET}"
      python $PLUGINS_DIR/spoofcheck/spoofcheck.py $TARGET | tee $LOOT_DIR/nmap/dns-$TARGET-email.txt 2>/dev/null
      echo ""
      echo -e "${OKGREEN}====================================================================================${RESET}"
      echo -e "$OKRED STARTING DOMAIN FLYOVER $RESET"
      echo -e "${OKGREEN}====================================================================================${RESET}"
      aquatone-discover -d $TARGET -t 100 --wordlist $PLUGINS_DIR/Sublist3r/subdomains.lst | tee $LOOT_DIR/nmap/aquatone-$TARGET-discover.txt 2>/dev/null
      aquatone-takeover -d $TARGET -t 100 | tee $LOOT_DIR/nmap/aquatone-$TARGET-takeovers.txt 2>/dev/null
      aquatone-scan -d $TARGET -t 100 -p80,443 | tee $LOOT_DIR/nmap/aquatone-$TARGET-ports.txt 2>/dev/null
      aquatone-gather -d $TARGET -t 100 | tee $LOOT_DIR/nmap/aquatone-$TARGET-gather.txt 2>/dev/null
      mkdir -p $LOOT_DIR/aquatone/ 2> /dev/null
      cp -Rf ~/aquatone/$TARGET $LOOT_DIR/aquatone/
      echo ""
      echo -e "${OKGREEN}====================================================================================${RESET}"
      echo -e "$OKRED CHECKING FOR SUBDOMAIN HIJACKING $RESET"
      echo -e "${OKGREEN}====================================================================================${RESET}"
      dig $TARGET CNAME | egrep -i "wordpress|instapage|heroku|github|bitbucket|squarespace|fastly|feed|fresh|ghost|helpscout|helpjuice|instapage|pingdom|surveygizmo|teamwork|tictail|shopify|desk|teamwork|unbounce|helpjuice|helpscout|pingdom|tictail|campaign|monitor|cargocollective|statuspage|tumblr|amazon|hubspot|cloudfront|modulus|unbounce|uservoice|wpengine|cloudapp" | tee $LOOT_DIR/nmap/takeovers-$TARGET.txt 2>/dev/null
      for a in `cat $LOOT_DIR/domains/domains-$TARGET-full.txt`; do dig $a CNAME | egrep -i "wordpress|instapage|heroku|github|bitbucket|squarespace|fastly|feed|fresh|ghost|helpscout|helpjuice|instapage|pingdom|surveygizmo|teamwork|tictail|shopify|desk|teamwork|unbounce|helpjuice|helpscout|pingdom|tictail|campaign|monitor|cargocollective|statuspage|tumblr|amazon|hubspot|cloudfront|modulus|unbounce|uservoice|wpengine|cloudapp" | tee $LOOT_DIR/nmap/takeovers-$a.txt 2>/dev/null; done;
      if [ "$SUBOVER" = "1" ]; then
        subover -l $LOOT_DIR/domains/domains-$TARGET-full.txt | tee $LOOT_DIR/nmap/takeovers-$TARGET-subover.txt 2>/dev/null
      fi
      echo -e "${OKGREEN}====================================================================================${RESET}"
      echo -e "$OKRED STARTING PUBLIC S3 BUCKET SCAN $RESET"
      echo -e "${OKGREEN}====================================================================================${RESET}"
      cd $PLUGINS_DIR/slurp/
      ./slurp-linux-amd64 domain --domain $TARGET | tee $LOOT_DIR/nmap/takeovers-$TARGET-s3-buckets.txt 2>/dev/null
    fi
    cd $INSTALL_DIR
    echo ""
  fi
  echo ""
  echo -e "${OKGREEN}====================================================================================${RESET}"
  echo -e "$OKRED RUNNING TCP PORT SCAN $RESET"
  echo -e "${OKGREEN}====================================================================================${RESET}"
  nmap -sS -T5 --open -Pn -p $DEFAULT_PORTS $TARGET -oX $LOOT_DIR/nmap/nmap-$TARGET.xml | tee $LOOT_DIR/nmap/nmap-$TARGET.txt
 
  port_80=`grep 'portid="80"' $LOOT_DIR/nmap/nmap-$TARGET.xml | grep open`
  port_443=`grep 'portid="443"' $LOOT_DIR/nmap/nmap-$TARGET.xml | grep open`
 
  if [ -z "$port_80" ];
  then
    echo -e "$OKRED + -- --=[Port 80 closed... skipping.$RESET"
  else
    echo -e "$OKORANGE + -- --=[Port 80 opened... running tests...$RESET"
    echo -e "${OKGREEN}====================================================================================${RESET}"
    echo -e "$OKRED CHECKING FOR WAF $RESET"
    echo -e "${OKGREEN}====================================================================================${RESET}"
    wafw00f http://$TARGET | tee $LOOT_DIR/web/waf-$TARGET-http 2> /dev/null
    sed -r "s/\x1B\[([0-9]{1,2}(;[0-9]{1,2})?)?[mGK]//g" $LOOT_DIR/web/waf-$TARGET-http > $LOOT_DIR/web/waf-$TARGET-http.txt 2> /dev/null
    echo -e "${OKGREEN}====================================================================================${RESET}"
    echo -e "$OKRED GATHERING HTTP INFO $RESET"
    echo -e "${OKGREEN}====================================================================================${RESET}"
    whatweb -a 3 http://$TARGET | tee $LOOT_DIR/web/whatweb-$TARGET-http 2> /dev/null
    sed -r "s/\x1B\[([0-9]{1,2}(;[0-9]{1,2})?)?[mGK]//g" $LOOT_DIR/web/whatweb-$TARGET-http > $LOOT_DIR/web/whatweb-$TARGET-http.txt 2> /dev/null
    echo -e "${OKGREEN}====================================================================================${RESET}"
    echo -e "$OKRED GATHERING SERVER INFO $RESET"
    echo -e "${OKGREEN}====================================================================================${RESET}"
    python3 $PLUGINS_DIR/wig/wig.py -d -q -t 50 http://$TARGET | tee $LOOT_DIR/web/wig-$TARGET-http
    sed -r "s/\x1B\[([0-9]{1,2}(;[0-9]{1,2})?)?[mGK]//g" $LOOT_DIR/web/wig-$TARGET-http > $LOOT_DIR/web/wig-$TARGET-http.txt 2> /dev/null
    echo -e "${OKGREEN}====================================================================================${RESET}"
    echo -e "$OKRED CHECKING HTTP HEADERS AND METHODS $RESET"
    echo -e "${OKGREEN}====================================================================================${RESET}"
    wget -qO- -T 1 --connect-timeout=3 --read-timeout=3 --tries=1 http://$TARGET |  perl -l -0777 -ne 'print $1 if /<title.*?>\s*(.*?)\s*<\/title/si' >> $LOOT_DIR/web/title-http-$TARGET.txt 2> /dev/null
    curl --connect-timeout 3 --max-time 3 -I -s -R http://$TARGET | tee $LOOT_DIR/web/headers-http-$TARGET.txt 2> /dev/null
    if [ "$PASSIVE_SPIDER" = "1" ]; then
      echo -e "${OKGREEN}====================================================================================${RESET}"
      echo -e "$OKRED RUNNING PASSIVE WEB SPIDER $RESET"
      echo -e "${OKGREEN}====================================================================================${RESET}"
      curl -sX GET "http://index.commoncrawl.org/CC-MAIN-2018-22-index?url=*.$TARGET&output=json" | jq -r .url | sort -u | tee $LOOT_DIR/web/spider-$TARGET.txt 2> /dev/null
    fi
    
    if [ "$BLACKWIDOW" == "1" ]; then
      echo -e "${OKGREEN}====================================================================================${RESET}"
      echo -e "$OKRED RUNNING ACTIVE WEB SPIDER $RESET"
      echo -e "${OKGREEN}====================================================================================${RESET}"
      blackwidow -u http://$TARGET -l 1 
      cat /usr/share/blackwidow/$TARGET/$TARGET-urls-sorted.txt >> $LOOT_DIR/web/spider-$TARGET.txt 2>/dev/null
    fi

    echo -e "${OKGREEN}====================================================================================${RESET}"
    echo -e "$OKRED RUNNING FILE/DIRECTORY BRUTE FORCE $RESET"
    echo -e "${OKGREEN}====================================================================================${RESET}"
    python3 $PLUGINS_DIR/dirsearch/dirsearch.py -u http://$TARGET -w $WEB_BRUTE_QUICK -x 400,403,404,405,406,429,502,503,504 -F -e php,asp,aspx,bak,zip,tar.gz,html,htm 
    cat $PLUGINS_DIR/dirsearch/reports/$TARGET/* 2> /dev/null
    cat $PLUGINS_DIR/dirsearch/reports/$TARGET/* > $LOOT_DIR/web/dirsearch-$TARGET.txt 2> /dev/null
    wget http://$TARGET/robots.txt -O $LOOT_DIR/web/robots-$TARGET-http.txt 2> /dev/null
    echo -e "${OKGREEN}====================================================================================${RESET}"
    echo -e "$OKRED SAVING SCREENSHOTS $RESET"
    echo -e "${OKGREEN}====================================================================================${RESET}"
    if [ ${DISTRO} == "blackarch"  ]; then
      /bin/CutyCapt --url=http://$TARGET --out=$LOOT_DIR/screenshots/$TARGET-port80.jpg --insecure --max-wait=1000 2> /dev/null
    else
      cutycapt --url=http://$TARGET --out=$LOOT_DIR/screenshots/$TARGET-port80.jpg --insecure --max-wait=1000 2> /dev/null
    fi
  fi
 
  if [ -z "$port_443" ];
  then
    echo -e "$OKRED + -- --=[Port 443 closed... skipping.$RESET"
  else
    echo -e "$OKORANGE + -- --=[Port 443 opened... running tests...$RESET"
    echo -e "${OKGREEN}====================================================================================${RESET}"
    echo -e "$OKRED CHECKING FOR WAF $RESET"
    echo -e "${OKGREEN}====================================================================================${RESET}"
    wafw00f https://$TARGET | tee $LOOT_DIR/web/waf-$TARGET-https 2> /dev/null
    sed -r "s/\x1B\[([0-9]{1,2}(;[0-9]{1,2})?)?[mGK]//g" $LOOT_DIR/web/waf-$TARGET-https > $LOOT_DIR/web/waf-$TARGET-https.txt 2> /dev/null
    echo -e "${OKGREEN}====================================================================================${RESET}"
    echo -e "$OKRED GATHERING HTTP INFO $RESET"
    echo -e "${OKGREEN}====================================================================================${RESET}"
    whatweb -a 3 https://$TARGET | tee $LOOT_DIR/web/whatweb-$TARGET-https  2> /dev/null
    sed -r "s/\x1B\[([0-9]{1,2}(;[0-9]{1,2})?)?[mGK]//g" $LOOT_DIR/web/whatweb-$TARGET-https > $LOOT_DIR/web/whatweb-$TARGET-https.txt 2> /dev/null
    echo -e "${OKGREEN}====================================================================================${RESET}"
    echo -e "$OKRED GATHERING SERVER INFO $RESET"
    echo -e "${OKGREEN}====================================================================================${RESET}"
    python3 $PLUGINS_DIR/wig/wig.py -d -q -t 50 https://$TARGET | tee $LOOT_DIR/web/wig-$TARGET-https
    sed -r "s/\x1B\[([0-9]{1,2}(;[0-9]{1,2})?)?[mGK]//g" $LOOT_DIR/web/wig-$TARGET-https > $LOOT_DIR/web/wig-$TARGET-https.txt 2> /dev/null
    echo -e "${OKGREEN}====================================================================================${RESET}"
    echo -e "$OKRED CHECKING HTTP HEADERS AND METHODS $RESET"
    echo -e "${OKGREEN}====================================================================================${RESET}"
    wget -qO- -T 1 --connect-timeout=3 --read-timeout=3 --tries=1 https://$TARGET |  perl -l -0777 -ne 'print $1 if /<title.*?>\s*(.*?)\s*<\/title/si' >> $LOOT_DIR/web/title-https-$TARGET.txt 2> /dev/null
    curl --connect-timeout 3 --max-time 3 -I -s -R https://$TARGET | tee $LOOT_DIR/web/headers-https-$TARGET.txt 2> /dev/null
    if [ "$PASSIVE_SPIDER" = "1" ]; then
      echo -e "${OKGREEN}====================================================================================${RESET}"
      echo -e "$OKRED RUNNING PASSIVE WEB SPIDER $RESET"
      echo -e "${OKGREEN}====================================================================================${RESET}"
      curl -sX GET "http://index.commoncrawl.org/CC-MAIN-2018-22-index?url=*.$TARGET&output=json" | jq -r .url | sort -u | tee $LOOT_DIR/web/spider-$TARGET.txt 2> /dev/null
    fi

    if [ "$BLACKWIDOW" == "1" ]; then
      echo -e "${OKGREEN}====================================================================================${RESET}"
      echo -e "$OKRED RUNNING ACTIVE WEB SPIDER $RESET"
      echo -e "${OKGREEN}====================================================================================${RESET}"
      blackwidow -u http://$TARGET -l 1
      cat /usr/share/blackwidow/$TARGET/$TARGET-urls-sorted.txt >> $LOOT_DIR/web/spider-$TARGET.txt 2>/dev/null
    fi

    echo -e "${OKGREEN}====================================================================================${RESET}"
    echo -e "$OKRED RUNNING FILE/DIRECTORY BRUTE FORCE $RESET"
    echo -e "${OKGREEN}====================================================================================${RESET}"
    python3 $PLUGINS_DIR/dirsearch/dirsearch.py -u https://$TARGET -w $WEB_BRUTE_QUICK -x 400,403,404,405,406,429,502,503,504 -F -e php,asp,aspx,bak,zip,tar.gz,html,htm 
    cat $PLUGINS_DIR/dirsearch/reports/$TARGET/* 2> /dev/null
    cat $PLUGINS_DIR/dirsearch/reports/$TARGET/* > $LOOT_DIR/web/dirsearch-$TARGET.txt 2> /dev/null
    wget https://$TARGET/robots.txt -O $LOOT_DIR/web/robots-$TARGET-https.txt 2> /dev/null
    if [ "$SSL" = "1" ]; then
      echo -e "${OKGREEN}====================================================================================${RESET}"
      echo -e "$OKRED GATHERING SSL/TLS INFO $RESET"
      echo -e "${OKGREEN}====================================================================================${RESET}"
      sslyze --resum --certinfo=basic --compression --reneg --sslv2 --sslv3 --hide_rejected_ciphers $TARGET | tee $LOOT_DIR/web/sslyze-$TARGET.txt 2> /dev/null
      sslscan --no-failed $TARGET | tee $LOOT_DIR/web/sslscan-$TARGET.raw 2> /dev/null
      sed -r "s/\x1B\[([0-9]{1,2}(;[0-9]{1,2})?)?[mGK]//g" $LOOT_DIR/web/sslscan-$TARGET.raw > $LOOT_DIR/web/sslscan-$TARGET.txt 2> /dev/null
    fi
    echo -e "${OKGREEN}====================================================================================${RESET}"
    echo -e "$OKRED SAVING SCREENSHOTS $RESET"
    echo -e "${OKGREEN}====================================================================================${RESET}"
    if [ ${DISTRO} == "blackarch"  ]; then
      /bin/CutyCapt --url=https://$TARGET --out=$LOOT_DIR/screenshots/$TARGET-port443.jpg --insecure --max-wait=1000 2> /dev/null
    else
      cutycapt --url=https://$TARGET --out=$LOOT_DIR/screenshots/$TARGET-port443.jpg --insecure --max-wait=1000 2> /dev/null
    fi
    echo -e "$OKRED[+]$RESET Screenshot saved to $LOOT_DIR/screenshots/$TARGET-port443.jpg"
  fi
  echo -e "${OKGREEN}====================================================================================${RESET}"
  echo -e "$OKRED SCAN COMPLETE! $RESET"
  echo -e "${OKGREEN}====================================================================================${RESET}"
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
  rm -f $INSTALL_DIR/.fuse_* 2> /dev/null
  if [ "$LOOT" = "1" ]; then
    loot
  fi
  exit
fi