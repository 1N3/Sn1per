if [ "$RECON" = "1" ]; then
  if [ "$SLACK_NOTIFICATIONS" == "1" ]; then
    /bin/bash "$INSTALL_DIR/bin/slack.sh" "[xerosecurity.com] •?((¯°·._.• Started Sn1per recon scan: $TARGET [$MODE] (`date +"%Y-%m-%d %H:%M"`) •._.·°¯))؟•"
  fi
  cp $LOOT_DIR/domains/domains-$TARGET-full.txt $LOOT_DIR/domains/domains_old-$TARGET.txt 2> /dev/null
  echo -e "${OKGREEN}====================================================================================${RESET}•x${OKGREEN}[`date +"%Y-%m-%d](%H:%M)"`${RESET}x•"
  echo -e "$OKRED GATHERING DNS SUBDOMAINS VIA SUBLIST3R $RESET"
  echo -e "${OKGREEN}====================================================================================${RESET}•x${OKGREEN}[`date +"%Y-%m-%d](%H:%M)"`${RESET}x•"
  if [ "$SUBLIST3R" = "1" ]; then
    python $PLUGINS_DIR/Sublist3r/sublist3r.py -d $TARGET -vvv -o $LOOT_DIR/domains/domains-$TARGET.txt 2>/dev/null
  fi
  if [ "$AMASS" = "1" ]; then
    echo -e "${OKGREEN}====================================================================================${RESET}•x${OKGREEN}[`date +"%Y-%m-%d](%H:%M)"`${RESET}x•"
    echo -e "$OKRED GATHERING DNS SUBDOMAINS VIA AMASS $RESET"
    echo -e "${OKGREEN}====================================================================================${RESET}•x${OKGREEN}[`date +"%Y-%m-%d](%H:%M)"`${RESET}x•"
    amass2.9 -ip -brute -active -o $LOOT_DIR/domains/domains-$TARGET-amass.txt -min-for-recursive 3 -d $TARGET 2>/dev/null
    cut -d, -f1 $LOOT_DIR/domains/domains-$TARGET-amass.txt 2>/dev/null | grep $TARGET > $LOOT_DIR/domains/domains-$TARGET-amass-sorted.txt
    cut -d, -f2 $LOOT_DIR/domains/domains-$TARGET-amass.txt 2>/dev/null > $LOOT_DIR/domains/domains-$TARGET-amass-ips-sorted.txt
  fi
  if [ "$SUBFINDER" = "1" ]; then
    echo -e "${OKGREEN}====================================================================================${RESET}•x${OKGREEN}[`date +"%Y-%m-%d](%H:%M)"`${RESET}x•"
    echo -e "$OKRED GATHERING DNS SUBDOMAINS VIA SUBFINDER (THIS COULD TAKE A WHILE...) $RESET"
    echo -e "${OKGREEN}====================================================================================${RESET}•x${OKGREEN}[`date +"%Y-%m-%d](%H:%M)"`${RESET}x•"
    subfinder -o $LOOT_DIR/domains/domains-$TARGET-subfinder.txt -b -d $TARGET -w $DOMAINS_DEFAULT -t 100 2>/dev/null
  fi
  echo -e "${OKGREEN}====================================================================================${RESET}•x${OKGREEN}[`date +"%Y-%m-%d](%H:%M)"`${RESET}x•"
  echo -e "$OKRED BRUTE FORCING DNS SUBDOMAINS VIA DNSCAN (THIS COULD TAKE A WHILE...) $RESET"
  echo -e "${OKGREEN}====================================================================================${RESET}•x${OKGREEN}[`date +"%Y-%m-%d](%H:%M)"`${RESET}x•"
  if [ "$DNSCAN" = "1" ]; then
    python $PLUGINS_DIR/dnscan/dnscan.py -d $TARGET -w $DOMAINS_QUICK -o $LOOT_DIR/domains/domains-dnscan-$TARGET.txt -i $LOOT_DIR/domains/domains-ips-$TARGET.txt
    cat $LOOT_DIR/domains/domains-dnscan-$TARGET.txt 2>/dev/null | grep $TARGET| awk '{print $3}' | sort -u >> $LOOT_DIR/domains/domains-$TARGET.txt 2> /dev/null
    dos2unix $LOOT_DIR/domains/domains-$TARGET.txt 2>/dev/null
  fi
  echo ""
  if [ "$CRTSH" = "1" ]; then
    echo -e "$OKRED ╔═╗╦═╗╔╦╗╔═╗╦ ╦$RESET"
    echo -e "$OKRED ║  ╠╦╝ ║ ╚═╗╠═╣$RESET"
    echo -e "$OKRED ╚═╝╩╚═ ╩o╚═╝╩ ╩$RESET"
    echo -e "${OKGREEN}====================================================================================${RESET}•x${OKGREEN}[`date +"%Y-%m-%d](%H:%M)"`${RESET}x•"
    echo -e "$OKRED GATHERING CERTIFICATE SUBDOMAINS $RESET"
    echo -e "${OKGREEN}====================================================================================${RESET}•x${OKGREEN}[`date +"%Y-%m-%d](%H:%M)"`${RESET}x•"
    echo -e "$OKBLUE"
    curl -s https://crt.sh/?q=%25.$TARGET > /tmp/curl.out && cat /tmp/curl.out | grep $TARGET | grep TD | sed -e 's/<//g' | sed -e 's/>//g' | sed -e 's/TD//g' | sed -e 's/\///g' | sed -e 's/ //g' | sed -n '1!p' | sort -u > $LOOT_DIR/domains/domains-$TARGET-crt.txt && cat $LOOT_DIR/domains/domains-$TARGET-crt.txt
    echo ""
    echo -e "${OKRED}[+] Domains saved to: $LOOT_DIR/domains/domains-$TARGET-full.txt"
  fi
  if [ "$CENSYS_SUBDOMAINS" = "1" ]; then
    echo -e "${OKGREEN}====================================================================================${RESET}•x${OKGREEN}[`date +"%Y-%m-%d](%H:%M)"`${RESET}x•"
    echo -e "$OKRED GATHERING CENSYS SUBDOMAINS $RESET"
    echo -e "${OKGREEN}====================================================================================${RESET}•x${OKGREEN}[`date +"%Y-%m-%d](%H:%M)"`${RESET}x•"
    python $PLUGINS_DIR/censys-subdomain-finder/censys_subdomain_finder.py --censys-api-id $CENSYS_APP_ID --censys-api-secret $CENSYS_API_SECRET $TARGET | egrep "\-" | awk '{print $2}' | tee $LOOT_DIR/domains/domains-$TARGET-censys.txt 2> /dev/null 
  fi
  if [ "$PROJECT_SONAR" = "1" ]; then
    echo -e "${OKGREEN}====================================================================================${RESET}•x${OKGREEN}[`date +"%Y-%m-%d](%H:%M)"`${RESET}x•"
    echo -e "$OKRED GATHERING PROJECT SONAR SUBDOMAINS $RESET"
    echo -e "${OKGREEN}====================================================================================${RESET}•x${OKGREEN}[`date +"%Y-%m-%d](%H:%M)"`${RESET}x•"
    curl -fsSL "https://dns.bufferover.run/dns?q=.$TARGET" | sed 's/\"//g' | cut -f2 -d "," |sort -u | grep $TARGET | tee $LOOT_DIR/domains/domains-$TARGET-projectsonar.txt 2> /dev/null 
  fi
  cat $LOOT_DIR/domains/domains-$TARGET-crt.txt 2> /dev/null > /tmp/curl.out 2> /dev/null
  cat $LOOT_DIR/domains/domains-$TARGET.txt 2> /dev/null >> /tmp/curl.out 2> /dev/null
  cat $LOOT_DIR/domains/domains-$TARGET-amass-sorted.txt 2> /dev/null >> /tmp/curl.out 2> /dev/null
  cat $LOOT_DIR/domains/domains-$TARGET-subfinder.txt 2> /dev/null >> /tmp/curl.out 2> /dev/null
  cat $LOOT_DIR/domains/domains-$TARGET-projectsonar.txt 2> /dev/null >> /tmp/curl.out 2> /dev/null
  cat $LOOT_DIR/domains/domains-$TARGET-censys.txt 2> /dev/null >> /tmp/curl.out 2> /dev/null
  cat $LOOT_DIR/domains/targets.txt 2> /dev/null >> /tmp/curl.out 2> /dev/null
  if [ "$ALT_DNS" = "1" ]; then
    echo -e "${OKGREEN}====================================================================================${RESET}•x${OKGREEN}[`date +"%Y-%m-%d](%H:%M)"`${RESET}x•"
    echo -e "$OKRED GATHERING ALTDNS SUBDOMAINS $RESET"
    echo -e "${OKGREEN}====================================================================================${RESET}•x${OKGREEN}[`date +"%Y-%m-%d](%H:%M)"`${RESET}x•"
    python2 "$INSTALL_DIR/plugins/altdns/altdns.py" -i /tmp/curl.out -w $INSTALL_DIR/wordlists/altdns.txt -o $LOOT_DIR/domains/domains-$TARGET-altdns.txt 2> /dev/null 
  fi
  if [ "$DNSGEN" = "1" ]; then
    echo -e "${OKGREEN}====================================================================================${RESET}•x${OKGREEN}[`date +"%Y-%m-%d](%H:%M)"`${RESET}x•"
    echo -e "$OKRED GATHERING DNSGEN SUBDOMAINS $RESET"
    echo -e "${OKGREEN}====================================================================================${RESET}•x${OKGREEN}[`date +"%Y-%m-%d](%H:%M)"`${RESET}x•"
    python3 "$INSTALL_DIR/plugins/dnsgen/dnsgen.py" /tmp/curl.out > $LOOT_DIR/domains/domains-$TARGET-dnsgen.txt 2> /dev/null 
  fi
  if [ "$MASS_DNS" = "1" ]; then
    echo -e "${OKGREEN}====================================================================================${RESET}•x${OKGREEN}[`date +"%Y-%m-%d](%H:%M)"`${RESET}x•"
    echo -e "$OKRED RUNNING MASSDNS ON SUBDOMAINS $RESET"
    echo -e "${OKGREEN}====================================================================================${RESET}•x${OKGREEN}[`date +"%Y-%m-%d](%H:%M)"`${RESET}x•"
    sort -u $LOOT_DIR/domains/domains-$TARGET-dnsgen.txt $LOOT_DIR/domains/domains-$TARGET-altdns.txt 2> /dev/null > $LOOT_DIR/domains/domains-$TARGET-alldns.txt 2> /dev/null 
    /usr/share/sniper/plugins/massdns/bin/massdns -s 5000 -r /usr/share/sniper/plugins/massdns/lists/resolvers.txt $LOOT_DIR/domains/domains-$TARGET-alldns.txt -o S -t AAAA -q -w $LOOT_DIR/domains/domains-$TARGET-massdns.txt
    awk -F ". " '{print $1}' $LOOT_DIR/domains/domains-$TARGET-massdns.txt | grep -v "*" | sort -u | tee $LOOT_DIR/domains/domains-$TARGET-massdns-sorted.txt
    cat $LOOT_DIR/domains/domains-$TARGET-massdns-sorted.txt 2> /dev/null >> /tmp/curl.out 2> /dev/null
    grep "CNAME" $LOOT_DIR/domains/domains-$TARGET-massdns.txt | awk '{print $3}' | grep -v "*" | sort -u | tee $LOOT_DIR/domains/domains-$TARGET-massdns-CNAME.txt
    grep "A " $LOOT_DIR/domains/domains-$TARGET-massdns.txt | awk '{print $3}' | grep -v "*" | sort -u | tee $LOOT_DIR/domains/domains-$TARGET-massdns-A-records.txt
  fi
  sort -u /tmp/curl.out 2> /dev/null > $LOOT_DIR/domains/domains-$TARGET-full.txt
  rm -f /tmp/curl.out 2> /dev/null
  diff $LOOT_DIR/domains/domains_old-$TARGET.txt $LOOT_DIR/domains/domains-$TARGET-full.txt 2> /dev/null | grep "> " 2> /dev/null | awk '{print $2}' 2> /dev/null > $LOOT_DIR/domains/domains_new-$TARGET.txt
  if [ "$SLACK_NOTIFICATIONS_DOMAINS_NEW" == "1" ]; then
    /bin/bash "$INSTALL_DIR/bin/slack.sh" postfile "$LOOT_DIR/domains/domains_new-$TARGET.txt"
  fi
  echo -e "$RESET"
  if [ "$SPOOF_CHECK" = "1" ]; then
    echo -e "${OKGREEN}====================================================================================${RESET}•x${OKGREEN}[`date +"%Y-%m-%d](%H:%M)"`${RESET}x•"
    echo -e "$OKRED CHECKING FOR EMAIL SECURITY $RESET"
    echo -e "${OKGREEN}====================================================================================${RESET}•x${OKGREEN}[`date +"%Y-%m-%d](%H:%M)"`${RESET}x•"
    python $PLUGINS_DIR/spoofcheck/spoofcheck.py $TARGET | tee $LOOT_DIR/nmap/email-$TARGET.txt 2>/dev/null
    echo ""
    if [ "$SLACK_NOTIFICATIONS_EMAIL_SECURITY" == "1" ]; then
      /bin/bash "$INSTALL_DIR/bin/slack.sh" postfile "$LOOT_DIR/nmap/email-$TARGET.txt"
    fi
  fi
  if [ "$SUBHIJACK_CHECK" = "1" ]; then
    echo -e "${OKGREEN}====================================================================================${RESET}•x${OKGREEN}[`date +"%Y-%m-%d](%H:%M)"`${RESET}x•"
    echo -e "$OKRED CHECKING FOR CNAME SUBDOMAIN HIJACKING $RESET"
    echo -e "${OKGREEN}====================================================================================${RESET}•x${OKGREEN}[`date +"%Y-%m-%d](%H:%M)"`${RESET}x•"
    grep -h "CNAME" $LOOT_DIR/nmap/takeovers-* 2>/dev/null | sort -u 2> /dev/null > $LOOT_DIR/nmap/takeovers_old-all.txt
    dig $TARGET CNAME | egrep -i "wordpress|instapage|heroku|github|bitbucket|squarespace|fastly|feed|fresh|ghost|helpscout|helpjuice|instapage|pingdom|surveygizmo|teamwork|tictail|shopify|desk|teamwork|unbounce|helpjuice|helpscout|pingdom|tictail|campaign|monitor|cargocollective|statuspage|tumblr|amazon|hubspot|modulus|unbounce|uservoice|wpengine|cloudapp" | tee $LOOT_DIR/nmap/takeovers-$TARGET.txt 2>/dev/null
    for a in `cat $LOOT_DIR/domains/domains-$TARGET-full.txt`; do dig $a CNAME | egrep -i "wordpress|instapage|heroku|github|bitbucket|squarespace|fastly|feed|fresh|ghost|helpscout|helpjuice|instapage|pingdom|surveygizmo|teamwork|tictail|shopify|desk|teamwork|unbounce|helpjuice|helpscout|pingdom|tictail|campaign|monitor|cargocollective|statuspage|tumblr|amazon|hubspot|modulus|unbounce|uservoice|wpengine|cloudapp" | tee $LOOT_DIR/nmap/takeovers-$a.txt 2>/dev/null; done;
    grep -h "CNAME" $LOOT_DIR/nmap/takeovers-* 2>/dev/null | sort -u 2> /dev/null | awk '{print $1 " " $4 " " $5}' | grep CNAME | sort -u > $LOOT_DIR/nmap/takeovers_new-all.txt
    diff $LOOT_DIR/nmap/takeovers_old-all.txt $LOOT_DIR/nmap/takeovers_new-all.txt 2> /dev/null | grep "> " | awk '{print $2 " " $3 " " $4}' | sort -u > $LOOT_DIR/nmap/takeovers_new-diff.txt 2> /dev/null
    if [ "$SLACK_NOTIFICATIONS_TAKEOVERS_NEW" == "1" ]; then
      /bin/bash "$INSTALL_DIR/bin/slack.sh" postfile "$LOOT_DIR/nmap/takeovers_new-diff.txt"
    fi
  fi
  if [ "$SUBOVER" = "1" ]; then
    echo -e "${OKGREEN}====================================================================================${RESET}•x${OKGREEN}[`date +"%Y-%m-%d](%H:%M)"`${RESET}x•"
    echo -e "$OKRED STARTING SUBOVER HIJACKING SCAN $RESET"
    echo -e "${OKGREEN}====================================================================================${RESET}•x${OKGREEN}[`date +"%Y-%m-%d](%H:%M)"`${RESET}x•"
    cp $LOOT_DIR/nmap/subover-$TARGET.txt $LOOT_DIR/nmap/subover_old-$TARGET.txt 2> /dev/null
    cd ~/go/src/github.com/Ice3man543/SubOver
    subover -l $LOOT_DIR/domains/domains-$TARGET-full.txt | tee $LOOT_DIR/nmap/subover-$TARGET 2>/dev/null
    sed -r "s/\x1B\[([0-9]{1,2}(;[0-9]{1,2})?)?[mGK]//g" $LOOT_DIR/nmap/subover-$TARGET > $LOOT_DIR/nmap/subover-$TARGET.txt 2> /dev/null
    rm -f $LOOT_DIR/nmap/subover-$TARGET 2> /dev/null
    diff $LOOT_DIR/nmap/subover_old-$TARGET.txt $LOOT_DIR/nmap/subover-$TARGET.txt 2> /dev/null | grep "> " 2> /dev/null | awk '{$1=""; print $0}' 2> /dev/null > $LOOT_DIR/nmap/subover_new-$TARGET.txt
    if [ "$SLACK_NOTIFICATIONS_SUBOVER_NEW" == "1" ]; then
      /bin/bash "$INSTALL_DIR/bin/slack.sh" postfile "$LOOT_DIR/nmap/subover_new-$TARGET.txt"
    fi
    cd $INSTALL_DIR
  fi
  if [ "$SUBJACK" = "1" ]; then
    echo -e "${OKGREEN}====================================================================================${RESET}•x${OKGREEN}[`date +"%Y-%m-%d](%H:%M)"`${RESET}x•"
    echo -e "$OKRED STARTING SUBJACK HIJACKING SCAN $RESET"
    echo -e "${OKGREEN}====================================================================================${RESET}•x${OKGREEN}[`date +"%Y-%m-%d](%H:%M)"`${RESET}x•"
    cp $LOOT_DIR/nmap/subjack-$TARGET.txt $LOOT_DIR/nmap/subjack_old-$TARGET.txt 2> /dev/null
    ~/go/bin/subjack -w $LOOT_DIR/domains/domains-$TARGET-full.txt -t $THREADS -timeout 30 -o $LOOT_DIR/nmap/subjack-$TARGET.txt -a -v
    diff $LOOT_DIR/nmap/subjack_old-$TARGET.txt $LOOT_DIR/nmap/subjack-$TARGET.txt 2> /dev/null | grep "> " 2> /dev/null | awk '{$1=""; print $0}' 2> /dev/null > $LOOT_DIR/nmap/subjack_new-$TARGET.txt
    if [ "$SLACK_NOTIFICATIONS_SUBJACK_NEW" == "1" ]; then
      /bin/bash "$INSTALL_DIR/bin/slack.sh" postfile "$LOOT_DIR/nmap/subjack_new-$TARGET.txt"
    fi
  fi
  if [ "$SLURP" = "1" ]; then
    echo -e "${OKGREEN}====================================================================================${RESET}•x${OKGREEN}[`date +"%Y-%m-%d](%H:%M)"`${RESET}x•"
    echo -e "$OKRED STARTING PUBLIC S3 BUCKET SCAN $RESET"
    echo -e "${OKGREEN}====================================================================================${RESET}•x${OKGREEN}[`date +"%Y-%m-%d](%H:%M)"`${RESET}x•"
    cd $PLUGINS_DIR/slurp/
    ./slurp-linux-amd64 domain --domain $TARGET | tee $LOOT_DIR/nmap/takeovers-$TARGET-s3-buckets.txt 2>/dev/null
    if [ "$SLACK_NOTIFICATIONS_S3_BUCKETS" == "1" ]; then
      /bin/bash "$INSTALL_DIR/bin/slack.sh" postfile "$LOOT_DIR/nmap/takeovers-$TARGET-s3-buckets.txt"
    fi
  fi
  if [ "$SUBNET_RETRIEVAL" = "1" ]; then
    echo -e "${OKGREEN}====================================================================================${RESET}•x${OKGREEN}[`date +"%Y-%m-%d](%H:%M)"`${RESET}x•"
    echo -e "$OKRED STARTING SUBNET RETRIEVAL $RESET"
    echo -e "${OKGREEN}====================================================================================${RESET}•x${OKGREEN}[`date +"%Y-%m-%d](%H:%M)"`${RESET}x•"
    curl -s -L --data "ip=$TARGET" https://2ip.me/en/services/information-service/provider-ip\?a\=act | grep -o -E '[0-9]{1,3}.[0-9]{1,3}.[0-9]{1,3}.[0-9]{1,3}/[0-9]{1,2}' | tee $LOOT_DIR/nmap/subnets-$TARGET.txt
    if [ "$SLACK_NOTIFICATIONS_SUBNETS" == "1" ]; then
      /bin/bash "$INSTALL_DIR/bin/slack.sh" postfile "$LOOT_DIR/nmap/subnets-$TARGET.txt"
    fi
  fi
  if [ "$SLACK_NOTIFICATIONS" == "1" ]; then
    /bin/bash "$INSTALL_DIR/bin/slack.sh" "[xerosecurity.com] •?((¯°·._.• Finished Sn1per recon scan: $TARGET [$MODE] (`date +"%Y-%m-%d %H:%M"`) •._.·°¯))؟•"
  fi
fi