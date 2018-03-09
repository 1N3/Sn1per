## CHANGELOG:
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
