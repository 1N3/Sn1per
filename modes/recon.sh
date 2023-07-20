if [[ "$RECON" = "1" ]]; then
  echo "[sn1persecurity.com] •?((¯°·._.• Started Sn1per recon scan: $TARGET [recon] (`date +"%Y-%m-%d %H:%M"`) •._.·°¯))؟•" >> $LOOT_DIR/scans/notifications_new.txt
  if [[ "$SLACK_NOTIFICATIONS" == "1" ]]; then
    /bin/bash "$INSTALL_DIR/bin/slack.sh" "[sn1persecurity.com] •?((¯°·._.• Started Sn1per recon scan: $TARGET [recon] (`date +"%Y-%m-%d %H:%M"`) •._.·°¯))؟•"
  fi

  touch $LOOT_DIR/domains/domains_old-$TARGET.txt 2> /dev/null
  cp $LOOT_DIR/domains/domains-$TARGET-full.txt $LOOT_DIR/domains/domains_old-$TARGET.txt 2> /dev/null
  
  if [[ "$SUBLIST3R" = "1" ]]; then
    echo -e "${OKGREEN}====================================================================================${RESET}•x${OKGREEN}[`date +"%Y-%m-%d](%H:%M)"`${RESET}x•"
    echo -e "$OKRED GATHERING DNS SUBDOMAINS VIA SUBLIST3R $RESET"
    echo -e "${OKGREEN}====================================================================================${RESET}•x${OKGREEN}[`date +"%Y-%m-%d](%H:%M)"`${RESET}x•"
    python3 /usr/share/sniper/plugins/Sublist3r/sublist3r.py -d $TARGET -vvv -o $LOOT_DIR/domains/domains-$TARGET.txt 2>/dev/null > /dev/null
    sed -ie 's/<BR>/\n/g' domains-$TARGET-full.txt 2> /dev/null
    mv -f $LOOT_DIR/domains/domains-$TARGET.txte $LOOT_DIR/domains/domains-$TARGET.txt 2> /dev/null
    wc -l $LOOT_DIR/domains/domains-$TARGET.txt 2> /dev/null
  fi
  if [[ "$AMASS" = "1" ]]; then
    echo -e "${OKGREEN}====================================================================================${RESET}•x${OKGREEN}[`date +"%Y-%m-%d](%H:%M)"`${RESET}x•"
    echo -e "$OKRED GATHERING DNS SUBDOMAINS VIA AMASS $RESET"
    echo -e "${OKGREEN}====================================================================================${RESET}•x${OKGREEN}[`date +"%Y-%m-%d](%H:%M)"`${RESET}x•"
    amass enum -ip -o $LOOT_DIR/domains/domains-$TARGET-amass.txt -rf /usr/share/sniper/plugins/massdns/lists/resolvers.txt -d $TARGET 2>/dev/null > /dev/null
    cut -d" " -f1 $LOOT_DIR/domains/domains-$TARGET-amass.txt 2>/dev/null | grep $TARGET > $LOOT_DIR/domains/domains-$TARGET-amass-sorted.txt
    cut -d" " -f2 $LOOT_DIR/domains/domains-$TARGET-amass.txt 2>/dev/null > $LOOT_DIR/ips/amass-ips-$TARGET.txt
    wc -l $LOOT_DIR/domains/domains-$TARGET-amass-sorted.txt
    wc -l $LOOT_DIR/ips/amass-ips-$TARGET.txt
    echo -e "${OKGREEN}====================================================================================${RESET}•x${OKGREEN}[`date +"%Y-%m-%d](%H:%M)"`${RESET}x•"
    echo -e "$OKRED GATHERING REVERSE WHOIS DNS SUBDOMAINS VIA AMASS $RESET"
    echo -e "${OKGREEN}====================================================================================${RESET}•x${OKGREEN}[`date +"%Y-%m-%d](%H:%M)"`${RESET}x•"
    amass intel -whois -d $TARGET > $LOOT_DIR/domains/domains-$TARGET-reverse-whois.txt 2> /dev/null
    wc -l $LOOT_DIR/domains/domains-$TARGET-reverse-whois.txt 2> /dev/null
  fi
  if [[ "$SUBFINDER" = "1" ]]; then
    echo -e "${OKGREEN}====================================================================================${RESET}•x${OKGREEN}[`date +"%Y-%m-%d](%H:%M)"`${RESET}x•"
    echo -e "$OKRED GATHERING DNS SUBDOMAINS VIA SUBFINDER $RESET"
    echo -e "$OKBLUE[*]$RESET Running: subfinder -o $LOOT_DIR/domains/domains-$TARGET-subfinder.txt -d $TARGET -t 100 $RESET"
    echo -e "${OKGREEN}====================================================================================${RESET}•x${OKGREEN}[`date +"%Y-%m-%d](%H:%M)"`${RESET}x•"
    subfinder -o $LOOT_DIR/domains/domains-$TARGET-subfinder.txt -d $TARGET -nW -rL /sniper/wordlists/resolvers.txt -t $THREADS 2>/dev/null > /dev/null
    wc -l $LOOT_DIR/domains/domains-$TARGET-subfinder.txt 2> /dev/null
  fi  
  if [[ "$DNSCAN" = "1" ]]; then
    echo -e "${OKGREEN}====================================================================================${RESET}•x${OKGREEN}[`date +"%Y-%m-%d](%H:%M)"`${RESET}x•"
    echo -e "$OKRED BRUTE FORCING DNS SUBDOMAINS VIA DNSCAN (THIS COULD TAKE A WHILE...) $RESET"
    echo -e "${OKGREEN}====================================================================================${RESET}•x${OKGREEN}[`date +"%Y-%m-%d](%H:%M)"`${RESET}x•"
    python3 $PLUGINS_DIR/dnscan/dnscan.py -d $TARGET -w $DOMAINS_QUICK -o $LOOT_DIR/domains/domains-dnscan-$TARGET.txt -i $LOOT_DIR/domains/domains-ips-$TARGET.txt
    cat $LOOT_DIR/domains/domains-dnscan-$TARGET.txt 2>/dev/null | grep $TARGET| awk '{print $3}' | sort -u >> $LOOT_DIR/domains/domains-$TARGET.txt 2> /dev/null
    dos2unix $LOOT_DIR/domains/domains-$TARGET.txt 2>/dev/null
    sed -ie 's/<BR>/\n/g' $LOOT_DIR/domains/domains-$TARGET.txt 2> /dev/null
    mv -f $LOOT_DIR/domains/domains-$TARGET.txte $LOOT_DIR/domains/domains-$TARGET.txt 2> /dev/null
    wc -l $LOOT_DIR/domains/domains-$TARGET.txt 2> /dev/null
  fi
  echo ""
  if [[ "$CRTSH" = "1" ]]; then
    echo -e "$OKRED ╔═╗╦═╗╔╦╗╔═╗╦ ╦$RESET"
    echo -e "$OKRED ║  ╠╦╝ ║ ╚═╗╠═╣$RESET"
    echo -e "$OKRED ╚═╝╩╚═ ╩o╚═╝╩ ╩$RESET"
    echo -e "${OKGREEN}====================================================================================${RESET}•x${OKGREEN}[`date +"%Y-%m-%d](%H:%M)"`${RESET}x•"
    echo -e "$OKRED GATHERING CERTIFICATE SUBDOMAINS $RESET"
    echo -e "${OKGREEN}====================================================================================${RESET}•x${OKGREEN}[`date +"%Y-%m-%d](%H:%M)"`${RESET}x•"
    echo -e "$RESET"
    curl -s https://crt.sh/?q=%25.$TARGET > $LOOT_DIR/domains/domains-$TARGET-presorted.txt
    cat $LOOT_DIR/domains/domains-$TARGET-presorted.txt | grep $TARGET | grep TD | sed -e 's/<//g' | sed -e 's/>//g' | sed -e 's/TD//g' | sed -e 's/BR/\n/g' | sed -e 's/\///g' | sed -e 's/ //g' | sed -n '1!p' | grep -v "*" | sort -u > $LOOT_DIR/domains/domains-$TARGET-crt.txt
    wc -l $LOOT_DIR/domains/domains-$TARGET-crt.txt 2> /dev/null
    echo ""
    echo -e "${OKRED}[+] Domains saved to: $LOOT_DIR/domains/domains-$TARGET-crt.txt"
  fi
  if [[ "$SPYSE" = "1" ]]; then
    echo -e "${OKGREEN}====================================================================================${RESET}•x${OKGREEN}[`date +"%Y-%m-%d](%H:%M)"`${RESET}x•"
    echo -e "$OKRED GATHERING SPYSE SUBDOMAINS $RESET"
    echo -e "${OKGREEN}====================================================================================${RESET}•x${OKGREEN}[`date +"%Y-%m-%d](%H:%M)"`${RESET}x•"
    echo -e "$OKBLUE"
    spyse -target $TARGET --subdomains | grep $TARGET > $LOOT_DIR/domains/domains-$TARGET-spyse.txt
    wc -l $LOOT_DIR/domains/domains-$TARGET-spyse.txt 2> /dev/null
  fi
  if [[ "$CENSYS_SUBDOMAINS" = "1" ]]; then
    echo -e "${OKGREEN}====================================================================================${RESET}•x${OKGREEN}[`date +"%Y-%m-%d](%H:%M)"`${RESET}x•"
    echo -e "$OKRED GATHERING CENSYS SUBDOMAINS $RESET"
    echo -e "${OKGREEN}====================================================================================${RESET}•x${OKGREEN}[`date +"%Y-%m-%d](%H:%M)"`${RESET}x•"
    python3 $PLUGINS_DIR/censys-subdomain-finder/censys_subdomain_finder.py --censys-api-id $CENSYS_APP_ID --censys-api-secret $CENSYS_API_SECRET $TARGET | egrep "\-" | awk '{print $2}' | egrep -v "Searching|Found" > $LOOT_DIR/domains/domains-$TARGET-censys.txt 2> /dev/null 
    wc -l $LOOT_DIR/domains/domains-$TARGET-censys.txt 2> /dev/null
  fi
  if [[ "$SHODAN" = "1" ]]; then
    echo -e "${OKGREEN}====================================================================================${RESET}•x${OKGREEN}[`date +"%Y-%m-%d](%H:%M)"`${RESET}x•"
    echo -e "$OKRED GATHERING SHODAN SUBDOMAINS $RESET"
    echo -e "${OKGREEN}====================================================================================${RESET}•x${OKGREEN}[`date +"%Y-%m-%d](%H:%M)"`${RESET}x•"
    shodan init $SHODAN_API_KEY
    shodan search "hostname:*.$TARGET" > $LOOT_DIR/domains/shodan-$TARGET.txt 2> /dev/null 
    awk '{print $3}' $LOOT_DIR/domains/shodan-$TARGET.txt 2> /dev/null | grep -v "\;" > $LOOT_DIR/domains/domains-$TARGET-shodan-sorted.txt 2> /dev/null
    awk '{print $1}' $LOOT_DIR/domains/shodan-$TARGET.txt 2> /dev/null >> $LOOT_DIR/ips/ips-all-unsorted.txt 2>/dev/null
    wc -l $LOOT_DIR/domains/domains-$TARGET-shodan-sorted.txt 2> /dev/null
    wc -l $LOOT_DIR/ips/ips-all-unsorted.txt 2> /dev/null
  fi
  if [[ "$PROJECT_SONAR" = "1" ]]; then
    echo -e "${OKGREEN}====================================================================================${RESET}•x${OKGREEN}[`date +"%Y-%m-%d](%H:%M)"`${RESET}x•"
    echo -e "$OKRED GATHERING PROJECT SONAR SUBDOMAINS $RESET"
    echo -e "${OKGREEN}====================================================================================${RESET}•x${OKGREEN}[`date +"%Y-%m-%d](%H:%M)"`${RESET}x•"
    curl -fsSL "https://dns.bufferover.run/dns?q=.$TARGET" | sed 's/\"//g' | cut -f2 -d "," | grep -v "<BR>" | sort -u | grep $TARGET > $LOOT_DIR/domains/domains-$TARGET-projectsonar.txt 2> /dev/null
    wc -l $LOOT_DIR/domains/domains-$TARGET-projectsonar.txt 2> /dev/null
  fi
  if [[ "$GITHUB_SUBDOMAINS" = "1" ]]; then
    echo -e "${OKGREEN}====================================================================================${RESET}•x${OKGREEN}[`date +"%Y-%m-%d](%H:%M)"`${RESET}x•"
    echo -e "$OKRED GATHERING GITHUB SUBDOMAINS $RESET"
    echo -e "${OKGREEN}====================================================================================${RESET}•x${OKGREEN}[`date +"%Y-%m-%d](%H:%M)"`${RESET}x•"
    python3 /usr/share/sniper/bin/github-subdomains.py -t $GITHUB_API_TOKEN -d $TARGET $LOOT_DIR/domains/domains-$TARGET-github.txt 2> /dev/null
  fi
  if [[ "$RAPIDDNS" = "1" ]]; then
    echo -e "${OKGREEN}====================================================================================${RESET}•x${OKGREEN}[`date +"%Y-%m-%d](%H:%M)"`${RESET}x•"
    echo -e "$OKRED GATHERING RAPIDDNS SUBDOMAINS $RESET"
    echo -e "${OKGREEN}====================================================================================${RESET}•x${OKGREEN}[`date +"%Y-%m-%d](%H:%M)"`${RESET}x•"
    curl -s "https://rapiddns.io/subdomain/$TARGET?full=1&down=1#exportData()" | grep -Eo "(http|https)://[a-zA-Z0-9./?=_-]*" | sort -u | grep "$TARGET" | cut -d\/ -f3 2> /dev/null > $LOOT_DIR/domains/domains-$TARGET-rapiddns.txt 2> /dev/null
  fi
  cat $LOOT_DIR/domains/domains-$TARGET-crt.txt 2> /dev/null > $LOOT_DIR/domains/domains-$TARGET-presorted.txt 2> /dev/null
  cat $LOOT_DIR/domains/domains-$TARGET-spyse.txt /dev/null >> $LOOT_DIR/domains/domains-$TARGET-presorted.txt 2> /dev/null
  cat $LOOT_DIR/domains/domains-$TARGET.txt 2> /dev/null >> $LOOT_DIR/domains/domains-$TARGET-presorted.txt 2> /dev/null
  cat $LOOT_DIR/domains/domains-$TARGET-amass-sorted.txt 2> /dev/null >> $LOOT_DIR/domains/domains-$TARGET-presorted.txt 2> /dev/null
  cat $LOOT_DIR/domains/domains-$TARGET-subfinder.txt 2> /dev/null >> $LOOT_DIR/domains/domains-$TARGET-presorted.txt 2> /dev/null
  cat $LOOT_DIR/domains/domains-$TARGET-projectsonar.txt 2> /dev/null >> $LOOT_DIR/domains/domains-$TARGET-presorted.txt 2> /dev/null
  cat $LOOT_DIR/domains/domains-$TARGET-censys.txt 2> /dev/null >> $LOOT_DIR/domains/domains-$TARGET-presorted.txt 2> /dev/null
  cat $LOOT_DIR/domains/domains-$TARGET-shodan-sorted.txt 2>/dev/null >> $LOOT_DIR/domains/domains-$TARGET-presorted.txt 2> /dev/null
  cat $LOOT_DIR/domains/domains-$TARGET-github.txt 2> /dev/null >> $LOOT_DIR/domains/domains-$TARGET-presorted.txt 2> /dev/null
  cat $LOOT_DIR/domains/domains-$TARGET-rapiddns.txt 2> /dev/null >> $LOOT_DIR/domains/domains-$TARGET-presorted.txt 2> /dev/null
  cat $LOOT_DIR/domains/targets.txt 2> /dev/null >> $LOOT_DIR/domains/domains-$TARGET-presorted.txt 2> /dev/null
  sed -i '/^$/d' $LOOT_DIR/domains/domains-$TARGET-presorted.txt 2> /dev/null
  sed -i '/^$/d' $LOOT_DIR/domains/domains-$TARGET.txt 2> /dev/null
  cat $LOOT_DIR/domains/domains-$TARGET.txt 2> /dev/null | grep -v "*" | grep -v "?" 2> /dev/null > $LOOT_DIR/domains/domains-$TARGET-presorted-nowildcards.txt
  wc -l $LOOT_DIR/domains/domains-$TARGET.txt 2> /dev/null
  if [[ "$SUBBRUTE_DNS" = "1" ]]; then
    echo -e "${OKGREEN}====================================================================================${RESET}•x${OKGREEN}[`date +"%Y-%m-%d](%H:%M)"`${RESET}x•"
    echo -e "$OKRED GATHERING SUBBRUTE SUBDOMAINS $RESET"
    echo -e "${OKGREEN}====================================================================================${RESET}•x${OKGREEN}[`date +"%Y-%m-%d](%H:%M)"`${RESET}x•"
    python3 "$INSTALL_DIR/plugins/massdns/scripts/subbrute.py" $INSTALL_DIR/wordlists/domains-all.txt $TARGET 2> /dev/null > $LOOT_DIR/domains/domains-$TARGET-subbrute.txt 2> /dev/null
    wc -l $LOOT_DIR/domains/domains-$TARGET-subbrute.txt 2> /dev/null
  fi
  if [[ "$ALT_DNS" = "1" ]]; then
    echo -e "${OKGREEN}====================================================================================${RESET}•x${OKGREEN}[`date +"%Y-%m-%d](%H:%M)"`${RESET}x•"
    echo -e "$OKRED GATHERING ALTDNS SUBDOMAINS $RESET"
    echo -e "${OKGREEN}====================================================================================${RESET}•x${OKGREEN}[`date +"%Y-%m-%d](%H:%M)"`${RESET}x•"
    echo "$TARGET" > /tmp/domain 2> /dev/null
    altdns -i /tmp/domain -w $INSTALL_DIR/wordlists/altdns.txt -o $LOOT_DIR/domains/domains-$TARGET-altdns.txt 2> /dev/null 
    wc -l $LOOT_DIR/domains/domains-$TARGET-altdns.txt 2> /dev/null
  fi
  if [[ "$DNSGEN" = "1" ]]; then
    echo -e "${OKGREEN}====================================================================================${RESET}•x${OKGREEN}[`date +"%Y-%m-%d](%H:%M)"`${RESET}x•"
    echo -e "$OKRED GATHERING DNSGEN SUBDOMAINS $RESET"
    echo -e "${OKGREEN}====================================================================================${RESET}•x${OKGREEN}[`date +"%Y-%m-%d](%H:%M)"`${RESET}x•"
    dnsgen /tmp/domain > $LOOT_DIR/domains/domains-$TARGET-dnsgen.txt 2> /dev/null 
    wc -l $LOOT_DIR/domains/domains-$TARGET-dnsgen.txt 2> /dev/null
  fi
  if [[ "$MASS_DNS" = "1" ]]; then
    echo -e "${OKGREEN}====================================================================================${RESET}•x${OKGREEN}[`date +"%Y-%m-%d](%H:%M)"`${RESET}x•"
    echo -e "$OKRED RUNNING MASSDNS ON SUBDOMAINS $RESET"
    echo -e "${OKGREEN}====================================================================================${RESET}•x${OKGREEN}[`date +"%Y-%m-%d](%H:%M)"`${RESET}x•"
    sort -u $LOOT_DIR/domains/domains-$TARGET-presorted-nowildcards.txt $LOOT_DIR/domains/domains-$TARGET-dnsgen.txt $LOOT_DIR/domains/domains-$TARGET-altdns.txt $LOOT_DIR/domains/domains-$TARGET-subbrute.txt 2> /dev/null > $LOOT_DIR/domains/domains-$TARGET-alldns.txt 2> /dev/null 
    wc -l $LOOT_DIR/domains/domains-$TARGET-alldns.txt 2> /dev/null
    massdns -r /usr/share/sniper/plugins/massdns/lists/resolvers.txt $LOOT_DIR/domains/domains-$TARGET-alldns.txt -o S -t A -w $LOOT_DIR/domains/domains-$TARGET-massdns.txt > /dev/null
    awk -F ". " '{print $1}' $LOOT_DIR/domains/domains-$TARGET-massdns.txt 2> /dev/null | grep -v "*" | sort -u > $LOOT_DIR/domains/domains-$TARGET-massdns-sorted.txt 2> /dev/null
    wc -l $LOOT_DIR/domains/domains-$TARGET-massdns-sorted.txt 2> /dev/null
    cat $LOOT_DIR/domains/domains-$TARGET-massdns-sorted.txt 2> /dev/null >> $LOOT_DIR/domains/domains-$TARGET-presorted.txt 2> /dev/null
    #grep "CNAME" $LOOT_DIR/domains/domains-$TARGET-massdns.txt | awk '{print $3}' | grep -v "*" | sort -u > $LOOT_DIR/domains/domains-$TARGET-massdns-CNAME.txt
    #wc -l $LOOT_DIR/domains/domains-$TARGET-massdns-CNAME.txt
    #grep "A " $LOOT_DIR/domains/domains-$TARGET-massdns.txt | awk '{print $3}' | grep -v "*" | sort -u > $LOOT_DIR/ips/massdns-A-records-$TARGET.txt
    #wc -l $LOOT_DIR/ips/massdns-A-records-$TARGET.txt
    #cat $LOOT_DIR/ips/massdns-A-records-$TARGET.txt >> $LOOT_DIR/ips/ips-all-unsorted.txt 2> /dev/null
    #wc -l $LOOT_DIR/ips/ips-all-unsorted.txt
  fi
  cat $LOOT_DIR/domains/domains-$TARGET-presorted.txt $LOOT_DIR/domains/domains-$TARGET-massdns-sorted.txt 2> /dev/null | sort -u 2> /dev/null > $LOOT_DIR/domains/domains-$TARGET-full.txt
  sed -ie 's/<BR>/\n/g' $LOOT_DIR/domains/domains-$TARGET-full.txt 2> /dev/null
  mv -f $LOOT_DIR/domains/domains-$TARGET-full.txte $LOOT_DIR/domains/domains-$TARGET-full.txt 2> /dev/null
  wc -l $LOOT_DIR/domains/domains-$TARGET-full.txt 2> /dev/null
  cat $LOOT_DIR/domains/domains-$TARGET-full.txt >> $LOOT_DIR/scans/updated.txt 2> /dev/null
  #rm -f $LOOT_DIR/domains/domains-$TARGET-presorted.txt 2> /dev/null
  diff $LOOT_DIR/domains/domains_old-$TARGET.txt $LOOT_DIR/domains/domains-$TARGET-full.txt 2> /dev/null | grep "> " 2> /dev/null | awk '{print $2}' 2> /dev/null > $LOOT_DIR/domains/domains_new-$TARGET.txt
  echo -e "${OKGREEN}====================================================================================${RESET}•x${OKGREEN}[`date +"%Y-%m-%d](%H:%M)"`${RESET}x•"
  echo -e "$OKRED NEW SUBDOMAINS $RESET"
  echo -e "${OKGREEN}====================================================================================${RESET}•x${OKGREEN}[`date +"%Y-%m-%d](%H:%M)"`${RESET}x•"
  wc -l $LOOT_DIR/domains/domains_new-$TARGET.txt 2> /dev/null
  cat $LOOT_DIR/domains/domains_new-$TARGET.txt 2> /dev/null

  if [[ $(wc -c $LOOT_DIR/domains/domains_new-$TARGET.txt 2> /dev/null | awk '{print $1}') > 3 ]]; then
    echo "[sn1persecurity.com] •?((¯°·._.• New domains detected on $TARGET (`date +"%Y-%m-%d %H:%M"`) •._.·°¯))؟•" >> $LOOT_DIR/scans/notifications_new.txt
    cat $LOOT_DIR/domains/domains_new-$TARGET.txt 2> /dev/null >> $LOOT_DIR/scans/notifications_new.txt 2> /dev/null 
    if [[ "$SLACK_NOTIFICATIONS_DOMAINS_NEW" == "1" ]]; then
      /bin/bash "$INSTALL_DIR/bin/slack.sh" "[sn1persecurity.com] •?((¯°·._.• New domains detected on $TARGET (`date +"%Y-%m-%d %H:%M"`) •._.·°¯))؟•"
      /bin/bash "$INSTALL_DIR/bin/slack.sh" postfile "$LOOT_DIR/domains/domains_new-$TARGET.txt"
    fi
  fi
  echo -e "$RESET"
  if [[ "$STATIC_GREP_SEARCH" = "1" ]]; then
    echo -e "${OKGREEN}====================================================================================${RESET}•x${OKGREEN}[`date +"%Y-%m-%d](%H:%M)"`${RESET}x•"
    echo -e "$OKRED DISPLAYING INTERESTING DOMAINS SEARCH $RESET"
    echo -e "${OKGREEN}====================================================================================${RESET}•x${OKGREEN}[`date +"%Y-%m-%d](%H:%M)"`${RESET}x•"
    egrep -iE "GREP_INTERESTING_SUBDOMAINS" $LOOT_DIR/domains/domains-$TARGET-full.txt 2> /dev/null | tee $LOOT_DIR/domains/domains_interesting-$TARGET.txt | head -n "$GREP_MAX_LINES"
  fi
  if [[ "$SUBHIJACK_CHECK" = "1" ]]; then
    echo -e "${OKGREEN}====================================================================================${RESET}•x${OKGREEN}[`date +"%Y-%m-%d](%H:%M)"`${RESET}x•"
    echo -e "$OKRED CHECKING FOR CNAME SUBDOMAIN HIJACKING $RESET"
    echo -e "${OKGREEN}====================================================================================${RESET}•x${OKGREEN}[`date +"%Y-%m-%d](%H:%M)"`${RESET}x•"
    grep -h "CNAME" $LOOT_DIR/nmap/takeovers-* 2>/dev/null | sort -u 2> /dev/null > $LOOT_DIR/nmap/takeovers_old-all.txt
    dig $TARGET CNAME | egrep -i "netlify|anima|bitly|wordpress|instapage|heroku|github|bitbucket|squarespace|fastly|feed|fresh|ghost|helpscout|helpjuice|instapage|pingdom|surveygizmo|teamwork|tictail|shopify|desk|teamwork|unbounce|helpjuice|helpscout|pingdom|tictail|campaign|monitor|cargocollective|statuspage|tumblr|amazon|hubspot|modulus|unbounce|uservoice|wpengine|cloudapp" | tee $LOOT_DIR/nmap/takeovers-$TARGET.txt 2>/dev/null
    for a in `cat $LOOT_DIR/domains/domains-$TARGET-full.txt`; do dig $a CNAME | egrep -i "netlify|wordpress|instapage|heroku|github|bitbucket|squarespace|fastly|feed|fresh|ghost|helpscout|helpjuice|instapage|pingdom|surveygizmo|teamwork|tictail|shopify|desk|teamwork|unbounce|helpjuice|helpscout|pingdom|tictail|campaign|monitor|cargocollective|statuspage|tumblr|amazon|hubspot|modulus|unbounce|uservoice|wpengine|cloudapp" | tee $LOOT_DIR/nmap/takeovers-$a.txt 2>/dev/null; done;
    grep -h "CNAME" $LOOT_DIR/nmap/takeovers-* 2>/dev/null | sort -u 2> /dev/null | awk '{print $1 " " $4 " " $5}' | grep CNAME | sort -u > $LOOT_DIR/nmap/takeovers_new-all.txt
    diff $LOOT_DIR/nmap/takeovers_old-all.txt $LOOT_DIR/nmap/takeovers_new-all.txt 2> /dev/null | grep "> " | awk '{print $2 " " $3 " " $4}' | sort -u > $LOOT_DIR/nmap/takeovers_new-diff.txt 2> /dev/null
    if [[ "$SLACK_NOTIFICATIONS_TAKEOVERS_NEW" == "1" ]]; then
      /bin/bash "$INSTALL_DIR/bin/slack.sh" postfile "$LOOT_DIR/nmap/takeovers_new-diff.txt"
    fi
  fi
  if [[ "$SUBOVER" = "1" ]]; then
    echo -e "${OKGREEN}====================================================================================${RESET}•x${OKGREEN}[`date +"%Y-%m-%d](%H:%M)"`${RESET}x•"
    echo -e "$OKRED STARTING SUBOVER HIJACKING SCAN $RESET"
    echo -e "${OKGREEN}====================================================================================${RESET}•x${OKGREEN}[`date +"%Y-%m-%d](%H:%M)"`${RESET}x•"
    cp $LOOT_DIR/nmap/subover-$TARGET.txt $LOOT_DIR/nmap/subover_old-$TARGET.txt 2> /dev/null
    cd ~/go/src/github.com/Ice3man543/SubOver
    subover -l $LOOT_DIR/domains/domains-$TARGET-full.txt | tee $LOOT_DIR/nmap/subover-$TARGET 2>/dev/null
    sed -r "s/\x1B\[([0-9]{1,2}(;[0-9]{1,2})?)?[mGK]//g" $LOOT_DIR/nmap/subover-$TARGET > $LOOT_DIR/nmap/subover-$TARGET.txt 2> /dev/null
    rm -f $LOOT_DIR/nmap/subover-$TARGET 2> /dev/null
    diff $LOOT_DIR/nmap/subover_old-$TARGET.txt $LOOT_DIR/nmap/subover-$TARGET.txt 2> /dev/null | grep "> " 2> /dev/null | awk '{$1=""; print $0}' 2> /dev/null > $LOOT_DIR/nmap/subover_new-$TARGET.txt
    if [[ "$SLACK_NOTIFICATIONS_SUBOVER_NEW" == "1" ]]; then
      /bin/bash "$INSTALL_DIR/bin/slack.sh" postfile "$LOOT_DIR/nmap/subover_new-$TARGET.txt"
    fi
    cd $INSTALL_DIR
  fi
  if [[ "$SUBJACK" = "1" ]]; then
    echo -e "${OKGREEN}====================================================================================${RESET}•x${OKGREEN}[`date +"%Y-%m-%d](%H:%M)"`${RESET}x•"
    echo -e "$OKRED STARTING SUBJACK HIJACKING SCAN $RESET"
    echo -e "${OKGREEN}====================================================================================${RESET}•x${OKGREEN}[`date +"%Y-%m-%d](%H:%M)"`${RESET}x•"
    cp $LOOT_DIR/nmap/subjack-$TARGET.txt $LOOT_DIR/nmap/subjack_old-$TARGET.txt 2> /dev/null
    ~/go/bin/subjack -w $LOOT_DIR/domains/domains-$TARGET-full.txt -c ~/go/src/github.com/haccer/subjack/fingerprints.json -t $THREADS -timeout 30 -o $LOOT_DIR/nmap/subjack-$TARGET.txt -a -v | egrep -v "Not Vulnerable"
    diff $LOOT_DIR/nmap/subjack_old-$TARGET.txt $LOOT_DIR/nmap/subjack-$TARGET.txt 2> /dev/null | grep "> " 2> /dev/null | awk '{$1=""; print $0}' 2> /dev/null > $LOOT_DIR/nmap/subjack_new-$TARGET.txt
    if [[ "$SLACK_NOTIFICATIONS_SUBJACK_NEW" == "1" ]]; then
      /bin/bash "$INSTALL_DIR/bin/slack.sh" postfile "$LOOT_DIR/nmap/subjack_new-$TARGET.txt"
    fi
  fi
  if [[ "$ASN_CHECK" = "1" ]]; then
    echo -e "${OKGREEN}====================================================================================${RESET}•x${OKGREEN}[`date +"%Y-%m-%d](%H:%M)"`${RESET}x•"
    echo -e "$OKRED RETRIEVING ASN INFO $RESET"
    echo -e "${OKGREEN}====================================================================================${RESET}•x${OKGREEN}[`date +"%Y-%m-%d](%H:%M)"`${RESET}x•"
    cd $LOOT_DIR/ips/ 2>/dev/null
    asnip -t $TARGET | tee $LOOT_DIR/ips/asn-$TARGET.txt 2>/dev/null
    mv $LOOT_DIR/ips/cidrs.txt $LOOT_DIR/ips/cidrs-$TARGET.txt 2>/dev/null
    mv $LOOT_DIR/ips/ips.txt $LOOT_DIR/ips/ips-$TARGET.txt 2> /dev/null 
    cd $INSTALL_DIR 2>/dev/null 
  fi
  if [[ "$SUBNET_RETRIEVAL" = "1" ]]; then
    echo -e "${OKGREEN}====================================================================================${RESET}•x${OKGREEN}[`date +"%Y-%m-%d](%H:%M)"`${RESET}x•"
    echo -e "$OKRED STARTING SUBNET RETRIEVAL $RESET"
    echo -e "${OKGREEN}====================================================================================${RESET}•x${OKGREEN}[`date +"%Y-%m-%d](%H:%M)"`${RESET}x•"
    curl -s -L --data "ip=$TARGET" https://2ip.me/en/services/information-service/provider-ip\?a\=act | grep -o -E '[0-9]{1,3}.[0-9]{1,3}.[0-9]{1,3}.[0-9]{1,3}/[0-9]{1,2}' | tee $LOOT_DIR/ips/subnets-$TARGET.txt
    if [[ "$SLACK_NOTIFICATIONS_SUBNETS" == "1" ]]; then
      /bin/bash "$INSTALL_DIR/bin/slack.sh" postfile "$LOOT_DIR/ips/subnets-$TARGET.txt"
    fi
  fi
  if [[ "$SCAN_ALL_DISCOVERED_DOMAINS" = "1" ]]; then
    echo -e "${OKGREEN}====================================================================================${RESET}•x${OKGREEN}[`date +"%Y-%m-%d](%H:%M)"`${RESET}x•"
    echo -e "$OKRED STARTING FLYOVER SCAN OF ALL DOMAINS $RESET"
    echo -e "${OKGREEN}====================================================================================${RESET}•x${OKGREEN}[`date +"%Y-%m-%d](%H:%M)"`${RESET}x•"
    sniper -f $LOOT_DIR/domains/domains-$TARGET-full.txt -m flyover -w $WORKSPACE
  fi
  echo "[sn1persecurity.com] •?((¯°·._.• Finished Sn1per scan: $TARGET [recon] (`date +"%Y-%m-%d %H:%M"`) •._.·°¯))؟•" >> $LOOT_DIR/scans/notifications_new.txt
  if [[ "$SLACK_NOTIFICATIONS" == "1" ]]; then
    /bin/bash "$INSTALL_DIR/bin/slack.sh" "[sn1persecurity.com] •?((¯°·._.• Finished Sn1per scan: $TARGET [recon] (`date +"%Y-%m-%d %H:%M"`) •._.·°¯))؟•"
  fi
fi
