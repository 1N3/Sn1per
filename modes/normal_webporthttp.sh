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
        PORT="80"
        SSL="false"
        source modes/web_autopwn.sh
    fi
fi 