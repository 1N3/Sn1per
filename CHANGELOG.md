## CHANGELOG:
* v9.2 - Added Tomba.io API integration via OSINT mode (Credit: @benemohamed)
* v9.2 - Fixed issue with gau tool not installing and updated GAU setting in confs
* v9.2 - Updated python2 to python3
* v9.2 - Removed Slurp tool
* v9.2 - Added BlackArch Dockerfile (Credit: @AnonymousWP)
* v9.2 - Updated DockerFile to latest Kali release (Credit: @AnonymousWP)
* v9.1 - Fixed issue with dirsearch installation/command syntax update
* v9.1 - Updated Nuclei sc0pe templates
* v9.1 - Fixed issue with Nuclei sc0pe parsers not working
* v9.1 - Fixed issue with GAU installer/commmand not working
* v9.1 - Fixed issue with passive URL fetching 
* v9.1 - Fixed issue with nuclei not being installed
* v9.1 - Removed error in hackertarget URL fetching
* v9.1 - Added dnsutils to installer to fix missing deps
* v9.1 - Fixed issue with gau in webscan modes not running
* v9.1 - Updated subfinder to latest version
* v9.1 - Added new email spoofing security checks to OSINT mode (-o)
* v9.1 - Removed spoofcheck.py
* v9.1 - Updated timeout settings for curl which was causing sockets/scans to hang
* v9.1 - Fixed issue with Nuclei symlink missing in installer
* v9.1 - Fixed issue with Nuclei sc0pe parser not parsing results correctly
* v9.1 - Fixed issue with Dirsearch not running due to invalid command settings
* v9.1 - Fixed issue with Nuclei templates not being installed
* v9.1 - Fixed issue with enum4linux command not being installed
* v9.1 - Fixed HackerTarget API integration
* v9.1 - Fixed issue with ping command not being installed
* v9.1 - Fixed issue with carriage returns in conf
* v9.1 - Fixed issue with DNS resolution in 'discover' mode scans causing duplicate hosts
* v9.1 - Fixed issue with bruteforce running automatically due to changes in conf file
* v9.1 - Added verbose scan notifications for disabled conf options
* v9.1 - Updated default aux mode options in default sniper.conf
* v9.0 - Added Fortinet FortiGate SSL VPN Panel Detected sc0pe template
* v9.0 - Added CVE-2020-17519 - Apache Flink Path Traversal sc0pe template
* v9.0 - Added RabbitMQ Management Interface Detected sc0pe template
* v9.0 - Added CVE-2020-29583 Zyxel SSH Hardcoded Credentials via BruteX
* v9.0 - Removed vulnscan NMap CSV updates/downloads to save space/bandwidth
* v9.0 - Added Nuclei sc0pe parser
* v9.0 - Added Nuclei vulnerability scanner
* v9.0 - Added Wordpress WPScan sc0pe vulnerability parser
* v9.0 - Fixed issue with wrong WPscan API key command
* v9.0 - Added CVE-2020-11738 - WordPress Duplicator plugin Directory Traversal sc0pe template
* v9.0 - Renamed AUTO_VULNSCAN setting to "VULNSCAN" in sniper.conf to perform vulnerability scans via 'normal' mode
* v8.9 - Tuned sniper.conf around performance for all scans and recon modes
* v8.9 - Added out of scope options to config
* v8.9 - Added automatic HTTP/HTTPS web scans and vulnerability scans to 'normal' mode
* v8.9 - Added SolarWinds Orion Panel Default Credentials sc0pe template
* v8.9 - Added SolarWinds Orion Panel sc0pe template
* v8.9 - Fixed issue with UDP port scans not working
* v8.9 - Fixed issue with theHarvester not running on Kali 2020.4
* v8.9 - Added WPScan API support
* v8.9 - Added CVE-2020-8209 - XenMobile-Citrix Endpoint Management Config Password Disclosure sc0pe template
* v8.9 - Added CVE-2020-8209 - XenMobile-Citrix Endpoint Management Path Traversal sc0pe template
* v8.9 - Removed verbose error for chromium on Ubuntu
* v8.9 - Added CVE-2020-8209 - Citrix XenMobile Server Path Traversal sc0pe template
* v8.9 - Fixed F+ in CSP Not Enforced sc0pe template
* v8.9 - Added CVE-2020-14815 - Oracle Business Intelligence Enterprise DOM XSS sc0pe template
* v8.9 - Fixed issue with dnscan not working in Kali 2020.3
* v8.9 - Fixed issue with screenshots not working in Ubuntu 2020
* v8.9 - Added Frontpage Service Password Disclosure sc0pe template
* v8.9 - Removed Yasuo tool
* v8.8 - Fixed issue with webscreenshot on Kali 2020.3+
* v8.8 - Fixed error in install.sh for theharvester sym link
* v8.8 - Fixed issue with flyover mode not capturing web screenshots
* v8.8 - Added automatic 'flyover' scans of all discovered domains for 'recon' mode
* v8.8 - Added static grep searching rules of all URL's and sub-domains (see sniper.conf for details)
* v8.8 - Added verbose status logging to flyover mode showing HTTP status/redirect/title, etc.
* v8.8 - Added integration for Port Scanner Add-on for Sn1per Professional
* v8.8 - Added enhanced scanning of all unique dynamic URL's via InjectX fuzzer
* v8.8 - Added CVE-2020-25213 - WP File Manager File Upload sc0pe template
* v8.8 - Added cPanel Login Found sc0pe template
* v8.8 - Added Wordpress WP-File-Manager Version Detected sc0pe template
* v8.8 - Added VMware vCenter Unauthenticated Arbitrary File Read sc0pe template
* v8.8 - Added PHP Composer Disclosure sc0pe template
* v8.8 - Added Git Config Disclosure sc0pe template
* v8.8 - Added updated NMap vulscan DB files
* v8.8 - Added CVE-2020-9047 - exacqVision Web Service Remote Code Execution sc0pe template
* v8.8 - Removed UDP port scan settings/options and combined with full portscan ports
* v8.8 - Added CVE-2019-8442 - Jira Webroot Directory Traversal sc0pe template
* v8.8 - Added CVE-2020-2034 - PAN-OS GlobalProtect OS Command Injection sc0pe template
* v8.8 - Added CVE-2020-2551 - Unauthenticated Oracle WebLogic Server Remote Code Execution sc0pe template
* v8.8 - Added CVE-2020-14181 - User Enumeration Via Insecure Jira Endpoint sc0pe template
* v8.8 - Added Smuggler HTTP request smuggling detection
* v8.8 - Added CVE-2020-0618 - Remote Code Execution SQL Server Reporting Services sc0pe template
* v8.8 - Added CVE-2020-5412 - Full-read SSRF in Spring Cloud Netflix sc0pe template
* v8.8 - Added Jaspersoft Detected sc0pe template
* v8.8 - Added improved dirsearch exclude options to all web file/dir searches
* v8.8 - Fixed naming conflict for theharvester
* v8.8 - Created backups of all NMap HTML reports for fullportonly scans
* v8.8 - Added line limit to GUA URL's displayed in console
* v8.7 - Added AvantFAX LOGIN Detected sc0pe template
* v8.7 - Updated web file bruteforce lists
* v8.7 - Added updated Slack API integration/notifications
* v8.7 - Added Arachni, Nikto, Nessus, NMap + 20 passive sc0pe vulnerability parsers
* v8.7 - Added CVE-2020-15129 - Open Redirect In Traefik sc0pe template
* v8.7 - Added MobileIron Login sc0pe template
* v8.7 - Added Revive Adserver XSS sc0pe template
* v8.7 - Added IceWarp Webmail XSS sc0pe template
* v8.7 - Added Mara CMS v7.5 XSS sc0pe template
* v8.7 - Added Administrative Privilege Escalation in SAP NetWeaver sc0pe template
* v8.7 - Added Magento 2.3.0 SQL Injection sc0pe template
* v8.7 - Added CVE-2020-15920 - Unauthenticated RCE at Mida eFramework sc0pe template
* v8.7 - Added CVE-2019-7192 - QNAP Pre-Auth Root RCE sc0pe template
* v8.7 - Added CVE-2020-10204 - Sonatype Nexus Repository RCE sc0pe template
* v8.7 - Added CVE-2020-13167 - Netsweeper WebAdmin unixlogin.php Python Code Injection sc0pe template
* v8.7 - Added CVE-2020-2140 - Jenkin AuditTrailPlugin XSS sc0pe template
* v8.7 - Added CVE-2020-7209 - LinuxKI Toolset 6.01 Remote Command Execution sc0pe template
* v8.7 - Added CVE-2019-16662 - rConfig 3.9.2 Remote Code Execution sc0pe template
* v8.7 - Added Sitemap.xml Detected sc0pe template
* v8.7 - Added Robots.txt Detected sc0pe template
* v8.7 - Added AWS S3 Public Bucket Listing sc0pe template
* v8.7 - Fixed logic error in stealth mode recon scans not running
* v8.7 - Added CVE-2020-7048 - WP Database Reset 3.15 Unauthenticated Database Reset sc0pe template
* v8.7 - Fixed F- detection in Wordpress Sc0pe templates
* v8.7 - Added CVE-2020-11530 - Wordpress Chop Slider 3 Plugin SQL Injection sc0pe template
* v8.7 - Added CVE-2019-11580 - Atlassian Crowd Data Center Unauthenticated RCE sc0pe template
* v8.7 - Added CVE-2019-16759 - vBulletin 5.x 0-Day Pre-Auth Remote Command Execution Bypass sc0pe template
* v8.6 - Added new Sn1per configuration flow that allows persistent user configurations and API key transfer
* v8.6 - Updated port lists to remove duplicate ports error and slim down list
* v8.6 - Updated PHP to 7.4
* v8.6 - Added CVE-2020-12720 - vBulletin Unauthenticaed SQLi
* v8.6 - Added CVE-2020-9757 - SEOmatic < 3.3.0 Server-Side Template Injection
* v8.6 - Added CVE-2020-1147 - Remote Code Execution in Microsoft SharePoint Server
* v8.6 - Added CVE-2020-3187 - Citrix Unauthenticated File Deletion
* v8.6 - Added CVE-2020-8193 - Citrix Unauthenticated LFI
* v8.6 - Added CVE-2020-8194 - Citrix ADC & NetScaler Gateway Reflected Code Injection
* v8.6 - Added CVE-2020-8982 - Citrix ShareFile StorageZones Unauthenticated Arbitrary File Read
* v8.6 - Added CVE-2020-9484 - Apache Tomcat RCE by deserialization
* v8.6 - Added Cisco VPN scanner template
* v8.6 - Added Tiki Wiki CMS scanner template
* v8.6 - Added Palo Alto PAN OS Portal scanner template
* v8.6 - Added SAP NetWeaver AS JAVA LM Configuration Wizard Detection
* v8.6 - Added delete task workspace function to remove running tasks
* v8.6 - Added CVE-2020-3452 - Cisco ASA/FTD Arbitrary File Reading Vulnerability Sc0pe template
* v8.6 - Updated theharvester command to exclude github-code search
* v8.6 - Updated theharvester installer to v3.1
* v8.6 - Added urlscan.io API to OSINT mode (-o)
* v8.6 - Added OpenVAS package to install.sh 
* v8.6 - Added Palo Alto GlobalProtect PAN-OS Portal Sc0pe template
* v8.6 - Fixed issue with Javascript downloader downloading localhost files instead of target
* v8.6 - Added CVE-2020-5902 F5 BIG-IP RCE sc0pe template
* v8.6 - Added CVE-2020-5902 F5 BIG-IP XSS sc0pe template
* v8.6 - Added F5 BIG-IP detection sc0pe template
* v8.6 - Added interesting ports sc0pe template
* v8.6 - Added components with known vulnerabilities sc0pe template
* v8.6 - Added server header disclosure sc0pe template
* v8.6 - Added SMBv1 enabled sc0pe template
* v8.6 - Removed verbose comment from stealth scan
* v8.5 - Added manual installer for Metasploit
* v8.5 - Added Phantomjs manual installer
* v8.5 - Added sc0pe template to check for default credentials via BruteX
* v8.5 - Added fullportscans to all 'web' mode scans to ensure full port coverage
* v8.5 - Fixed issue with 2nd stage OSINT scans not running
* v8.5 - Added port values to sc0pe engine to define port numbers
* v8.5 - Fixed issue with LinkFinder not working
* v8.5 - Fixed issue with Javascript link parser
* v8.5 - Added phantomjs dependency to fix webscreenshots on Ubuntu
* v8.5 - Added http-default-accounts NMap NSE to check for default web credentials
* v8.5 - Fixed several issues with install.sh to resolve deps on Ubuntu and Kali 2020.2
* v8.5 - Removed larger wordlists to reduce install size of Sn1per
* v8.5 - Added 20+ new active/passive sc0pe templates
* v8.5 - Fixed issue with installer on latest Kali and Docker builds
* v8.5 - Fixed custom installer for Arachni
* v8.5 - Fixed Dockerfile with updated Kali image (CC. @stevemcilwain)
* v8.4 - Added project "Sc0pe" active/passive vulnerability scanner
* v8.4 - Added 68 new active sc0pe templates
* v8.4 - Added 14 new passive sc0pe templates
* v8.4 - Added OWASP ZAP API integration
* v8.4 - Added 8 new Sn1per configuration templates (see /usr/share/sniper/conf/)
* v8.4 - Added Gau (https://github.com/lc/gau)
* v8.4 - Added rapiddns subdomain retrieval
* v8.4 - Updated web content wordlists
* v8.4 - Improved efficiency of 'web' and 'recon' mode scans
* v8.4 - Disabled legacy Metasploit web exploits (check Sn1per conf to re-enable)
* v8.4 - Fixed issue with dirsearch asterisk being used incorrectly
* v8.4 - Fixed issue with airstrike mode not updated Sn1per Professional v8.0 host list
* v8.4 - Fixed issue with webtech re.error: invalid group reference 1 at position 130
* v8.3 - Added Github subdomain retrieval (requires API key/conf options enabled)
* v8.3 - Added NMAP_OPTIONS setting to sniper.conf to configure optional NMap scan settings
* v8.3 - Added option to specify custom Sn1per configuration via (-c) switch
* v8.3 - Created several custom config files to select from, including: bug_bounty_quick, bug_bounty_max_javascript, super_stealth_mode, webpwn_only + more
* v8.3 - Added workspace --export option to backup/export a workspace
* v8.3 - Added flyover mode tuning options to sniper.conf
* v8.3 - Added GitGraber automated Github leak search (https://github.com/hisxo/gitGraber)
* v8.3 - Added static Javascript parsing for sub-domains, URL's, path relative links and comments
* v8.3 - Added js-beautifier
* v8.3 - Added LinkFinder Javascript link finder (https://github.com/GerbenJavado/LinkFinder)
* v8.3 - Added fprobe HTTP probe checker (https://github.com/theblackturtle/fprobe)
* v8.3 - Added Cisco RV320 and RV325 Unauthenticated Remote Code Execution CVE-2019-1653 MSF exploit
* v8.3 - Improved performance of 'stealth' and 'recon' modes
* v8.3 - Updated default port lists
* v8.3 - Improved performance of all port scans
* v8.3 - Added fix for missing Amass package
* v8.3 - Added sniper.conf options for OPENVAS_HOST and OPENVAS_PORT selection for remote instances
* v8.3 - Improved 'vulnscan' mode via OpenVAS to scan the same asset multiple times with improved error handling
* v8.2 - Added root priv check to sniper script to run
* v8.2 - Added NMap port change notifications via Slack
* v8.2 - Fixed issue with firefox not loading on Kali Linux 2020.1 
* v8.2 - Fixed issue with Masswebscan mode not working
* v8.2 - Added Rails file exposure exploit CVE-2019-5418
* v8.2 - Updated wordlist selections to fingerprint common vulnerable applications
* v8.2 - Added h8mail compromised credentials check to OSINT (-o) mode
* v8.2 - Added Kali start menu app & icon for Sn1per
* v8.2 - Added check for insecure SSL/TLS connections
* v8.2 - Added NMAP_OPTIONS setting in ~/.sniper.conf to configure optional NMap settings
* v8.2 - Fixed issue with ManageEngine MSF exploit payload
* v8.2 - Added Spyse sub-domain enumeration tool (https://github.com/zeropwn/spyse.py)
* v8.2 - Fixed issue with Subjack (open /src/github.com/haccer/subjack/fingerprints.json: no such file or directory)
* v8.1 - Added Citrix Gateway Arbitary Code Execution CVE-2019-19781 vulnerability detection
* v8.1 - Added Pulse Secure VPN Arbitrary File Disclosure CVE-2019-11510 exploit
* v8.1 - Added --data-length=50 for NMap IPS evasion
* v8.1 - Removed NMap vulscan script due to F+ results
* v8.1 - Fixed issue with CRT.SH sub-domain retrieval
* v8.1 - Updated Kali Linux keyring package
* v8.1 - Fixed "[: ==: unary operator expected" in all code
* v8.1 - Updated Sn1per Professional autoload settings
* v8.1 - Updated web brute force wordlists
* v8.1 - Removed null and debug errors from passive spider API output
* v8.1 - Updated Commoncrawl index repo
* v8.1 - Updated DockerFile repository
* v8.1 - Fixed issue with -dh flag to delete host with Sn1per Pro v8.0
* v8.1 - Fixed issue with subfinder missing
* v8.1 - Fixed issue with 7zip missing
* v8.1 - Added check for Ubuntu to install.sh automatically
* v8.0 - Added ASnip tool to retrieve ASN's via 'recon' mode
* v8.0 - Added Shodan sub-domain lookup
* v8.0 - Added script timeout flag for NMap scripts
* v8.0 - Fixed issue with dnsenum getting stuck on gathering dns info stage
* v8.0 - Added option to force upgrade/install.sh without user prompt (ie. ./install.sh force)
* v8.0 - Fixed issue with theHarvester package on Ubuntu systems
* v8.0 - Fixed error "[: ==: unary operator expected" in all modes
* v8.0 - Added net-tools package for Ubuntu OS deps
* v7.4 - Added LDAP anomyous search to port 389/tcp checks (Shoutout @D0rkerDevil)
* v7.4 - Added Java RMI dump registry scan checks and exploits to port 8001/tcp (Shoutout @D0rkerDevil)
* v7.4 - Added CheckPoint Firewall-1 SecuRemote Topology Service Hostname Disclosure MSF module
* v7.4 - Added virtualhost scanning via web mode
* v7.4 - Added Gobuster
* v7.4 - Addd URLCrazy DNS alterations check to OSINT mode
* v7.4 - Added Ultratools Whois Lookups to OSINT mode
* v7.4 - Added Email-Format.com Email Retreival to OSINT mode
* v7.4 - Added Metasploit OSINT email retrieval to OSINT mode
* v7.4 - Added Hackertarget URL API retrieval to web modes
* v7.4 - Fixed error in massvulnscan mode
* v7.4 - Fixed issue with webscreenshot.py not running
* v7.4 - Added reverse whois DNS search via AMass
* v7.4 - Added MassDNS IP's to master sorted IP list 
* v7.4 - Fixed issue with MassDNS installation
* v7.4 - Fixed bad path with DNSGen 
* v7.4 - Fixed issue with AMass not running
* v7.4 - Improved performance of AltDNS/DNSgen/MassDNS retrieval
* v7.4 - Changed webscreenshot.py setting to use chrome browser and increased timeout
* v7.4 - Fixed issue with missing xmlstarlet package for OpenVAS scans
* v7.4 - Improved active web spider URL consolidation
* v7.3 - Added CVE-2019-15107 Webmin <= 1.920 - Unauthenticated RCE MSF exploit
* v7.3 - Added massdns plugin
* v7.3 - Added altdns plugin
* v7.3 - Added dnsgen plugin
* v7.3 - Updated web file/dir wordlists from public exploits and honeypots
* v7.3 - Added time stamps to all commands
* v7.3 - Removed CloudFront from domain hijacking checks
* v7.3 - Removed snmp-brute.nse script due to scan issues
* v7.3 - Fixed issue with discover scan workspace names
* v7.3 - Fixed issue with DockerFile (sed: can't read /usr/bin/msfdb: No such file or directory)
* v7.3 - Fixed issue with installer on docker not having pip installed
* v7.3 - Fixed issue with port 161 not being referenced correctly in scans
* v7.2 - Added experimental OpenVAS API integration
* v7.2 - Improved Burpsuite 2.x API integration with vuln reporting
* v7.2 - Added hunter.io API integration to recon mode scans
* v7.2 - Added Cisco IKE Key Disclosure MSF exploit
* v7.2 - Added JBoss MSF vuln scanner module
* v7.2 - Added Apache CouchDB RCE MSF exploit
* v7.2 - Added IBM Tivoli Endpoint Manager POST Query Buffer Overflow exploit
* v7.2 - Added Java RMI MSF scanner
* v7.2 - New scan mode "vulnscan"
* v7.2 - New scan mode "massportscan"
* v7.2 - New scan mode "massweb"
* v7.2 - New scan mode "masswebscan"
* v7.2 - New scan mode "massvulnscan"
* v7.2 - Added additional Slack API notification settings
* v7.2 - Improved NMap port detection and scan modes
* v7.2 - Fixed issue with Censys API being enabled by default
* v7.2 - Fixed verbose errors in subjack/subover tools
* v7.2 - Fixed issue with NMap http scripts not working
* v7.1 - Added BlueKeep CVE-2019-0708 MSF scanner
* v7.1 - Added automatic workspace generation for single target scans
* v7.1 - Added new slack.sh API integration script
* v7.1 - Added differential Slack notifications for new domains, new URL's and various scan outputs
* v7.1 - Added vulners and vulscan NMap scripts
* v7.1 - Added installer and support for Debian, Parrot and Ubuntu OS (install_debian.sh) (CC. @imhaxormad)
* v7.1 - Fixed various issues with the DockerFile
* v7.1 - Fixed/added Metasploit LHOST/LPORT values to all exploits based on sniper.conf settings
* v7.1 - Fixed issue with Amass/Golang 1.11 not installing correctly
* v7.0 - Added "webscan" mode for automated Burpsuite 2.x and Arachni web application scans only
* v7.0 - Added Slack API notifications (Disabled by default..check ~/.sniper.conf)
* v7.0 - Added new command switch to add daily, weekly or monthly sniper scheduled scans... check README
* v7.0 - Added scheduled scan tasks command switch (Needs additional configuration to setup... check README)
* v7.0 - Added Axis2 authenticated deployer MSF exploit
* v7.0 - Added Axis2 login brute force module
* v7.0 - Added subjack tool to check for subdomain hijacking
* v7.0 - Added sorted IP lists under $LOOT_DIR/ips/ips-all-sorted.txt
* v7.0 - Added subnet retrieval for all 'recon' mode scans under $LOOT_DIR/nmap/subnets-$TARGET.txt
* v7.0 - Added Webscreenshot.py and disabled cutycapt from default config
* v7.0 - Added Gobuster (Disabled by default..check ~/.sniper.conf)
* v7.0 - Fixed issue with SubOver not working due to bad path
* v7.0 - Fixed issue with flyover mode running 2x 
* v6.3 - Added Drupal RESET Unserialize RCE CVE-2019-6340
* v6.2 - Added Glassfish Admin traversal MSF exploit 
* v6.2 - Added ElasticSearch Java Injection MSF RCE exploit
* v6.2 - Added WebTech web fingerprinting tool
* v6.2 - Added censys subdomain retrieval and API key config
* v6.2 - Added project sonar sub-domain retrieval
* v6.2 - Added command switch to remove workspace (-d)
* v6.2 - Added command switch to remove host (-dh)
* v6.2 - Added DockerFile to run Sn1per in Docker (CC. Hariom Vashisth <hariom.devops@gmail.com>)
* v6.2 - Changed option to automatically import all NMap XML's into Metasploit's DB
* v6.2 - Changed option to automatically load Sn1per Professional's report when scans complete
* v6.2 - Added config option to enable/disable subdomain hijacking checks in sniper.conf
* v6.2 - Fixed issue with sniper --list command having invalid reference
* v6.2 - Fixed issue with theharvester not running
* v6.1 - Added automated web scanning via Burpsuite Pro 2.x API for all 'web' mode scans
* v6.1 - Added Waybackmachine URL retrieval to all web scans
* v6.1 - Converted all exploits to Metasploit
* v6.1 - Added configuration options to set LHOST/LPORT for all Metasploit exploits in sniper.conf
* v6.1 - Added improved web brute forcing dictionaries for all scan modes
* v6.1 - Added individual logging for all tools under the loot directory
* v6.1 - Added new sniper.conf options to enabled/disable all plugins and change settings per user
* v6.1 - Fixed issue with CMSMap install/usage
* v6.1 - Fixed issue with WPScan gem dependency missing (public_suffix)
* v6.1 - Fixed timeout setting in cutycapt
* v6.1 - Fixed issue with theharvester not running correctly
* v6.1 - Fixed issue with Amass not running due to invalid command line options in latest release
* v6.1 - Fixed issue with Sn1per Professional notepad.html missing
* v6.1 - Cleaned up plugins and install dependencies list
* v6.0 - Improved scan options for discover mode scans
* v6.0 - Fixed issue with pip3 dependency package missing
* v6.0 - Removed iceweasel from install.sh to fix apt error
* v5.9 - Fixed issue with auto updates not notifying users of updates
* v5.8 - Fixed issue with subfinder not working due to lack of wordlist switch
* v5.8 - Fixed missing osint directory/file paths
* v5.7 - Added libSSH auth bypass scanner CVE-2018-10933
* v5.7 - Added HTTP PUT method RCE MSF exploit
* v5.7 - Added sniper.conf scan configuration file to customize sniper environments by user
* v5.7 - Added modular scan mode source files
* v5.7 - Updated wordlists for improved performance and results
* v5.7 - Fixed issue with DNScan using an invalid path
* v5.6 - Changed automatic report generation to "ON" for Sn1per Pro users
* v5.5 - Added new multi-threaded high speed "flyover" mode added
* v5.5 - Added new scan status mode via (sniper --status) command
* v5.5 - Apache Struts CVE-2018-11776 RCE exploit
* v5.5 - Added Android Insecure ADB RCE auto exploit
* v5.5 - Added Apache Tomcat CVE-2017-12617 RCE exploit
* v5.5 - Added Oracle WebLogic WLS-WSAT Component Deserialisation RCE CVE-2017-10271 MSF exploit
* v5.5 - Added BlackWidow web application scanner with INJECTX fuzzer
* v5.5 - Added CVE-2018-15473 SSH user enumeration script
* v5.5 - Minor wordlist updates for web file brute forcing
* v5.4 - Updated Golang in install.sh
* v5.3 - Updated AMass repo in install.sh
* v5.3 - Removed CloudFail
* v5.3 - Fixed issue with subfinder missing brute force list
* v5.3 - Fixed issue with invalid dnsscan reference
* v5.2 - Added SubOver subdomain takeover scanner
* v5.2 - Added Subfinder subdomain enumeration tool
* v5.2 - Added Amass subdomain enumeration tool
* v5.2 - Added configurable modules/plugins to sniper script
* v5.2 - Added MS17-010 SMB Etternal Blue MSF exploit
* v5.2 - Added MSF Postgresql login scanner
* v5.2 - Added passive web spider
* v5.2 - Added WebDav metasploit aux modules
* v5.2 - Added NetBIOS NMap/MSF enumeration
* v5.2 - Added SMB MSF enumeration
* v5.2 - Added NSF MSF enumeration
* v5.2 - Added SSH MSF enumeration
* v5.2 - Added BadBlue Passthru MSF exploit
* v5.2 - Added SMB GPP MSF aux module
* v5.2 - Added Intel AMT MSF scanner
* v5.2 - Added MySQL MSF scanner
* v5.2 - Added MS03-026 DCOM RCE MSF exploit
* v5.2 - Added VNC no auth MSF scanner
* v5.2 - Added FTP MSF version scanner
* v5.2 - Added FTP anonymous access MSF scanner
* v5.2 - Added MS12-020 RDP MSF scanner
* v5.2 - Added MS10-061 Spoolss MSF exploit
* v5.2 - Added MS15-034 Sys Memory Dump MSF exploit
* v5.2 - Added MS06-040 Netapi MSF exploit
* v5.2 - Added MS05-039 PNP MSF exploit
* v5.2 - Added MS12-020 Max Channels RDP scanner
* v5.2 - Added JBoss status MSF scanner
* v5.2 - Added Apache Struts 2 REST Plugin XStream RCE check
* v5.2 - Added Apache Tomcat UTF8 Traversal MSF exploit
* v5.2 - Added Apache OPTIONS Bleed MSF exploit
* v5.2 - Added HP ILO Auth Bypass MSF exploit
* v5.2 - Added Jooma Comfields SQL injection MSF exploit
* v5.1 - Added dnscan to install.sh and updated sniper references which were broken
* v5.1 - Changed default brute force list for dnscan to improve performance of scans
* v5.1 - Removed CloudHunter and SubOver references (CC. 爱上平顶山)
* v5.0 - Added Sn1per Pro reporting interface (see https://sn1persecurity.com for more details)
* v5.0 - Added GPON Router RCE auto exploit 
* v5.0 - Added Cloudapp.net Azure subdomain takeover check
* v5.0 - Added Cisco ASA Directory Traversal auto exploit (CVE-2018-0296)
* v5.0 - Added Wig Web Information Gatherer
* v5.0 - Added Dirsearch with custom dirsearch wordlists (quick, normal, full)
* v5.0 - Fixed bug in installer/upgrade which copied the local dir contents to the install dir
* v5.0 - Improved scan performance while taking web screenshots 
* v5.0 - Fixed repo issue with Slurp (Shoutz to @ifly53e)
* v5.0 - Fixed issues with wrong ports listed in port scans (Shoutz to @ifly53e)
* v5.0 - Minor code fixes and typos corrected (Shoutz to @ifly53e)
* v5.0 - Updated "discover" mode scans for improved performance
* v4.5 - Added Apache Struts 2 CVE-2017-9805 and CVE-2017-5638 detection
* v4.5 - Added dirsearch web/file brute forcing
* v4.5 - Added smart file/directory brute forcing to all scan modes.
* v4.5 - Added subdomain brute force scan option to Sublist3r scan.
* v4.4 - Fixed issue with sniper nuke and airstrike modes not running.
* v4.4 - Added improved SNMP checks via NMap/Metasploit.
* v4.4 - Resolved dependency issue for nfs-common package.
* v4.4 - Fixed bug in sniper -fp command switch.
* v4.3 - Fixed bug in version info.
* v4.2 - Fixed bad merge in 4.1 causing sniper to break.
* v4.1 - Fixed a few bugs with various command line switches for airstrike and nuke modes.
* v4.1 - Fixed issue with path relative file inclusion via the -f flag. You can now include just the local filename (sniper -f targets.txt).
* v4.0 - Added new command switch options for all sniper scans (see --help for details)
* v4.0 - Added HTML formatted report for all workspaces to display screenshots, headers, reports and open ports
* v4.0 - Added optional scan options such as --recon, --osint, --fullportonly --bruteforce, etc. to selectively enable scan modules. (see --help for details) 
* v4.0 - Improved Yasou scan options to include existing NMap XML files
* v4.0 - Added automatic HTML/TXT/PDF reporting for all scans by default
* v4.0 - Updated default workspace directory to store all loot files by $TARGET name or $WORKSPACE alias
* v4.0 - Added screenshot and header retrieval to loot storage
* v4.0 - Updated NMAP SMB enum script
* v3.0 - Improved performance of various sniper modes
* v3.0 - Added Aquatone domain flyover tool
* v3.0 - Added slurp S3 public AWS scanner
* v3.0 - Updated Sub-domain hijacking site list
* v3.0 - Changed look and feel of console output to help readability
* v3.0 - Added online/offline check to implement changes to scans when in online vs. offline mode
* v2.9 - New improved fullportonly scan mode
* v2.9 - Added online check to see if there's an active internet connection
* v2.9 - Changed default browser to firefox to clear up errors in loot commmand
* v2.9 - Created uninstall.sh script to uninstall sniper
* v2.9 - Removed automatic workspace creation per scan
* v2.9 - Added curl timeout in update command to fix lag
* v2.9 - Fixed minor NMap UDP scan flag issue
* v2.9 - Added Metagoofil
* v2.9 - Updated theharvester scan options to include more results
* v2.8 - Improved discovery mode scan performance and output
* v2.8 - Improved fullportonly scan performance
* v2.8 - Improved startup performance options
* v2.8 - Added Cansina web/file brute force tool
* v2.8 - Added webporthttp and webporthttps modes
* v2.8 - Added custerd software enumeration tool
* v2.7 - Fixed issue with sniper update command and install.sh not running
* v2.7 - Fixed errors with GooHak
* v2.7 - Fixed syntax errors in sniper conditional statements 
* v2.7 - Added CloudFail 
* v2.7 - Fixed issue with [: ==: unary operator expected errors
* v2.6 - Added Blackarch Linux support 
* v2.6 - Added $BROWSER variable to set default browser
* v2.5g - Updated README with update command
* v2.5f - Fixes for various bugs reported and fixed by @ifly53e (https://github.com/1N3/Sn1per/pull/89)
* v2.5e - Fixed issue with port 3128/tcp checks (CC. @ifly53e)
* v2.5d - Added searchsploit option for (-v) to search all terms (CC. @ifly53e)
* v2.5c - Added various improvements to 'discover' mode scans
* v2.5b - Removed NMap script checks for 'fullportonly' mode
* v2.5a - Added auto-updates to check and download new versions
* v2.5a - Fixed issue with install.sh to resolve pip aha error
* v2.5a - Added libxml2-utils to install.sh to meet dependencies
* v2.5 - Added HTML report generation via sniper 'loot' command
* v2.5 - Added automatic NMap searchsploit integration to find exploits
* v2.5 - Added various improvements to Sn1per discovery scan mode
* v2.5 - Fixed issue with IIS BoF NMap script (CC. ifly53e)
* v2.4f - Fixed issue with upper NMap port range(CC. DaveW)
* v2.4e - Added NMap no ping switch to all scans
* v2.4d - Fixed issue with rpcinfo install script
* v2.4d - Fixed issue with Arachni install script
* v2.4c - Added loot and $TARGET sanity checks (CC. @menzow)
* v2.4b - Fixed issue with discovery scan output file (CC. @ifly53e)
* v2.4b - Fixed issue with Intel AMT RCE port list
* v2.4a - Added all NMap script checks via 'fullportonly' mode
* v2.4a - Added JBoss JMX Console Beanshell Deployer WAR Upload and Deployment Metasploit exploit
* v2.4a - Added Java RMI RCE NMap/Metasploit detection
* v2.4a - Added INTEL-SA-00075 (Intel AMT) vulnerability NMap script
* v2.4 - Added detection for open X11 servers
* v2.4 - Added IIS6 Win2k3 RCE NMap script
* v2.4 - Added option to disable Google Hacking queries via Firefox
* v2.3d - Fixed issue with loot command
* v2.3c - Added Apache Struts 2 RCE NMap script
* v2.3c - Added Apache Struts 2 RCE NMap exploit
* v2.3b - Changed NMap scan options to exclude ping sweeps (-P0)
* v2.3a - Fixed minor issue with MSSQL NMap script command (CC. @helo86)
* v2.3 - Fixed minor issues with missing $TARGET definitions for NMap (CC. @helo86)
* v2.2f - Added various optimizations and minor code fixes
* v2.2e - Changed NMap scan options (removed -P0 flag)
* v2.2d - Added MongoDB checks
* v2.2d - Improved NMap scanning options
* v2.2c - Added CouchDB checks
* v2.2c - Updated Sub-domain takeover list
* v2.2b - Added fullportonly mode to do exclusive full port scans
* v2.2b - Fixed minor issue with Metasploit Pro not starting
* v2.2b - Fixed minor issue with sniper loot command
* v2.2a - Fixed minor issue with loot function
* v2.2 - Added auto Metasploit Pro & Zenmap GUI integration
* v2.2 - Added Sn1per workspaces to loot directory
* v2.1d - Added crt.sh sub-domain check
* v2.1d - Removed blank screenshots from loot directory
* v2.1c - Fixed issue with install.sh install directories
* v2.1b - Added automatic Metasploit NMap xml imports for loot directory
* v2.1b - Removed Zenmap
* v2.1a - Separated Arachni reports for port 80/443/tcp
* v2.1a - Fixed NMap full port scan options
* v2.1 - Added Arachni with auto HTML web reporting (web mode only)
* v2.1 - Added full NMap detailed port scans
* v2.1 - Added port 4443/tcp checks
* v2.1 - Added META tag scans for web apps
* v2.1 - Removed Uniscan from web mode
* v2.1 - Removed SQLMap from web mode
* v2.0b - Added help option --help
* v2.0a - Fixed issue with ssh-audit
* v2.0a - Fixed issue with 'discover' mode
* v2.0 - Updated sub-domain takeover list
* v2.0 - Improved scan performance for stealth, airstrike and discover modes
* v2.0 - Removed jexboss due to clear screen issue with output
* v2.0 - Auto loot directory sorting for all tools
* v2.0 - Updated install.sh package list
* v1.9c - Enabled BruteX automated brute force attacks
* v1.9b - Fixed MSSQL port 1433/tcp port scan check (@hacktrack)
* v1.9a - Removed testssl script from stealth mode scans
* v1.9 - Added Ubuntu docker image for Sn1per (@menzow)
* v1.9 - Added automatic loot directory sorting for all modes
* v1.9 - Added MSSQL port 1433/tcp checks
* v1.9 - Added SNMP port 162/tcp checks (@hexageek)
* v1.9 - Added nslookup to install.sh
* v1.9 - Fixed install.sh dependency duplicates
* v1.8c - Added -A option to all NMap port scans
* v1.8c - Fixed install.sh permission issue
* v1.8c - Fixed install.sh cleanup options
* v1.8c - Added ssh-audit
* v1.8c - Added install directory (/usr/share/sniper/) to install script for universal access
* v1.8c - Fixed issue with Metasploit SSH scans
* v1.8c - Added auto-update to install.sh to automatically pull latest github release
* v1.8b - Fixed bug with NMap UDP scan options
* v1.8b - Fixed install.sh dependencies 
* v1.8b - Fixed jexboss options
* v1.8a - Updated sub-domain hijack list of domains (CC: th3gundy)
* v1.8 - Added sub-domain hijack scans for all sub-domains
* v1.8 - Added auto explort of all sub-domains to /domains directory
* v1.8 - Added additional stealth and airstrike checks for port 80 and 443
* v1.8 - Fixed issue with theHarvester not working with google
* v1.7g - Added email security/spoofing checks
* v1.7f - Added Zenmap XML auto-imports 
* v1.7f - Added ClamAV RCE Nmap script
* v1.7e - Fixed minor issue with airstrike and nuke mode
* v1.7e - Fixed minor issues with discover mode
* v1.7e - Added minor cosmetic improvements to reports
* v1.7e - Disabled automatic brute forcing by default
* v1.7e - Added automatic brute force setting in script vars
* v1.7d - Added sslyze
* v1.7d - Added 'discover' mode for full subnet scans
* v1.7d - Added verbosity to scan tasks to separate sub-tasks better
* v1.7c - Added plain text reporting 
* v1.7c - Improved loot directory structure and sorting
* v1.7b - Fixed issue with airstrike mode not scanning correctly
* v1.7b - Improved passive recon performance
* v1.7a - Improved NMap http scan performance
* v1.7a - Removed joomscan due to verbosity issues
* v1.7 - Added uniscan web vulnerability scanner
* v1.7 - Added joomscan Joomla scanner
* v1.7 - Improved web scan performance
* v1.7 - Fixed issue with inurlbr output
* v1.7 - Added remote desktop viewing for RDP connections
* v1.7 - Added experimental Metasploit exploit for Apache Struts RCE (CVE-2016-3081)
* v1.6e - Added reporting option for nobrute mode (CC. @mero01)
* v1.6e - Improved SMB scan performance/optimization added
* v1.6d - Improved NMap scan performance options
* v1.6d - Added xprobe2 OS finger printing tool
* v1.6d - Added jexbos JBoss autopwn
* v1.6d - Merged fix for theharvester package (CC. @RubenRocha)
* v1.6d - Merged fix for SuperMicroScanner (CC. @mero01)
* v1.6c - Add report mode for web scans
* v1.6c - Fixed issues with Sublist3r and theharvester
* v1.6c - Added Shocker Shellshock exploitation scanner
* v1.6b - Added Sublist3r sub-domain brute tool
* v1.6b - Added cutycapt web screenshot util
* v1.6a - Added improvements to recon phase
* v1.6a - Fixed small issue with 3rd party extension
* v1.6a - Various improvements to overall optimization of scans
* v1.6a - Added new "web" mode for full web application scans 
* v1.6 - Added 4 new modes including: stealth, port, airstrike and nuke
* v1.6 - Added Java de-serialization scanner
* v1.6 - Added reporting option to output to console and text file for all scans
* v1.6 - Added option to set Sn1per full path for universal command line access
* v1.6 - Added in DirBuster for web file brute forcing
* v1.6 - Fixed issue with sderr errors in TheHarvester
* v1.5e - Removed shodan command line tool due to issues
* v1.5e - Fixed wafwoof installation in kali 2.0
* v1.5d - Fixed minor issues with port 513/tmp and 514/tcp checks
* v1.5c - Fixed issue which broke link to sniper directory
* v1.5b - Added Squid Proxy checks port 3128/tcp
* v1.5b - Fixed shodan setup options in install.sh
* v1.5b - Fixed syntax error with theHarvester in install.sh
* v1.5a - Fixed syntax error with port 8081 checks
* v1.5a - Added Arachni integration
* v1.5a - Added vsftpd, proftpd, mysql, unrealircd auto exploits
* v1.5 - Added Metasploit scan and auto-exploit modules
* v1.5 - Added additional port checks
* v1.5 - Added full TCP/UDP NMap XML output
* v1.5 - Auto tune scan for either IP or hostname/domain
* v1.4h - Added auto IP/domain name scan configurations
* v1.4g - Added finger enumeration scripts
* v1.4g - Fixed nmap -p 445 target issue
* v1.4g - Fixed smtp-enum target issue
* v1.4f - Fixed BruteX directory bug
* v1.4e - Fixed reported errors install.sh
* v1.4e - Added auto-upgrade option to install.sh for existing Sn1per installs
* v1.4d - Fixed missing rake gem install dependency
* v1.4c - Reordered 3rd party extensions
* v1.4b - Fixed install.sh executable references
* v1.4b - Fixed Yasou dependencies in install.sh
* v1.4b - Fixed minor issues with BruteX loot directory
* v1.4 - Added Yasou for automatic web form brute forcing
* v1.4 - Added MassBleed for SSL vulnerability detection
* v1.4 - Added Breach-Miner for detection of breached accounts
* v1.4 - Fixed minor errors with nmap
* v1.4 - Removed debug output from goohak from displaying on console
