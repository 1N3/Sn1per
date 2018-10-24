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
    python $PLUGINS_DIR/dnscan/dnscan.py -d $TARGET -w $DOMAINS_DEFAULT -o $LOOT_DIR/domains/domains-dnscan-$TARGET.txt -i $LOOT_DIR/domains/domains-ips-$TARGET.txt
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
  python $PLUGINS_DIR/spoofcheck/spoofcheck.py $TARGET | tee $LOOT_DIR/nmap/email-$TARGET.txt 2>/dev/null
  echo ""
  echo -e "${OKGREEN}====================================================================================${RESET}"
  echo -e "$OKRED STARTING DOMAIN FLYOVER $RESET"
  echo -e "${OKGREEN}====================================================================================${RESET}"
  aquatone-discover -d $TARGET -t 100 --wordlist $PLUGINS_DIR/Sublist3r/subdomains.lst | tee $LOOT_DIR/nmap/aquatone-$TARGET-discover 2>/dev/null
  sed -r "s/\x1B\[([0-9]{1,2}(;[0-9]{1,2})?)?[mGK]//g" $LOOT_DIR/nmap/aquatone-$TARGET-discover > $LOOT_DIR/nmap/aquatone-$TARGET-discover.txt 2> /dev/null
  rm -f $LOOT_DIR/nmap/aquatone-$TARGET-discover 2> /dev/null
  aquatone-takeover -d $TARGET -t 100 | tee $LOOT_DIR/nmap/aquatone-$TARGET-takeovers 2>/dev/null
  sed -r "s/\x1B\[([0-9]{1,2}(;[0-9]{1,2})?)?[mGK]//g" $LOOT_DIR/nmap/aquatone-$TARGET-takeovers > $LOOT_DIR/nmap/aquatone-$TARGET-takeovers.txt 2> /dev/null
  rm -f $LOOT_DIR/nmap/aquatone-$TARGET-takeovers 2> /dev/null
  aquatone-scan -d $TARGET -t 100 -p80,443 | tee $LOOT_DIR/nmap/aquatone-$TARGET-ports 2>/dev/null
  sed -r "s/\x1B\[([0-9]{1,2}(;[0-9]{1,2})?)?[mGK]//g" $LOOT_DIR/nmap/aquatone-$TARGET-ports > $LOOT_DIR/nmap/aquatone-$TARGET-ports.txt 2> /dev/null
  rm -f $LOOT_DIR/nmap/aquatone-$TARGET-ports 2> /dev/null
  aquatone-gather -d $TARGET -t 100 | tee $LOOT_DIR/nmap/aquatone-$TARGET-gather.txt 2>/dev/null
  sed -r "s/\x1B\[([0-9]{1,2}(;[0-9]{1,2})?)?[mGK]//g" $LOOT_DIR/nmap/aquatone-$TARGET-gather > $LOOT_DIR/nmap/aquatone-$TARGET-gather.txt 2> /dev/null
  rm -f $LOOT_DIR/nmap/aquatone-$TARGET-gather 2> /dev/null
  mkdir -p $LOOT_DIR/aquatone/ 2> /dev/null
  cp -Rf ~/aquatone/$TARGET $LOOT_DIR/aquatone/
  echo ""
  echo -e "${OKGREEN}====================================================================================${RESET}"
  echo -e "$OKRED CHECKING FOR SUBDOMAIN HIJACKING $RESET"
  echo -e "${OKGREEN}====================================================================================${RESET}"
  dig $TARGET CNAME | egrep -i "wordpress|instapage|heroku|github|bitbucket|squarespace|fastly|feed|fresh|ghost|helpscout|helpjuice|instapage|pingdom|surveygizmo|teamwork|tictail|shopify|desk|teamwork|unbounce|helpjuice|helpscout|pingdom|tictail|campaign|monitor|cargocollective|statuspage|tumblr|amazon|hubspot|cloudfront|modulus|unbounce|uservoice|wpengine|cloudapp" | tee $LOOT_DIR/nmap/takeovers-$TARGET.txt 2>/dev/null
  for a in `cat $LOOT_DIR/domains/domains-$TARGET-full.txt`; do dig $a CNAME | egrep -i "wordpress|instapage|heroku|github|bitbucket|squarespace|fastly|feed|fresh|ghost|helpscout|helpjuice|instapage|pingdom|surveygizmo|teamwork|tictail|shopify|desk|teamwork|unbounce|helpjuice|helpscout|pingdom|tictail|campaign|monitor|cargocollective|statuspage|tumblr|amazon|hubspot|cloudfront|modulus|unbounce|uservoice|wpengine|cloudapp" | tee $LOOT_DIR/nmap/takeovers-$a.txt 2>/dev/null; done;
  if [ "$SUBOVER" = "1" ]; then
    cd $PLUGINS_DIR/SubOver/
    python subover.py -l $LOOT_DIR/domains/domains-$TARGET-full.txt | tee $LOOT_DIR/nmap/subover-$TARGET 2>/dev/null
    sed -r "s/\x1B\[([0-9]{1,2}(;[0-9]{1,2})?)?[mGK]//g" $LOOT_DIR/nmap/subover-$TARGET > $LOOT_DIR/nmap/subover-$TARGET.txt 2> /dev/null
    rm -f $LOOT_DIR/nmap/takeovers-$TARGET-subover 2> /dev/null
    cd $INSTALL_DIR
  fi
  echo -e "${OKGREEN}====================================================================================${RESET}"
  echo -e "$OKRED STARTING PUBLIC S3 BUCKET SCAN $RESET"
  echo -e "${OKGREEN}====================================================================================${RESET}"
  cd $PLUGINS_DIR/slurp/
  ./slurp-linux-amd64 domain --domain $TARGET | tee $LOOT_DIR/nmap/takeovers-$TARGET-s3-buckets.txt 2>/dev/null
fi