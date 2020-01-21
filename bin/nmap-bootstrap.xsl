<?xml version="1.0" encoding="utf-8"?>
<!--
Nmap Bootstrap XSL
Creative Commons BY-SA
Andreas Hontzia (@honze_net)
-->
<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform">
  <xsl:output method="html" encoding="utf-8" indent="yes" doctype-system="about:legacy-compat"/>
  <xsl:template match="/">
    <html lang="en">
      <head>
        <link rel="stylesheet" href="https://maxcdn.bootstrapcdn.com/bootstrap/3.3.7/css/bootstrap.min.css" integrity="sha384-BVYiiSIFeK1dGmJRAkycuHAHRg32OmUcww7on3RYdg4Va+PmSTsz/K68vbdEjh4u" crossorigin="anonymous"/>
        <link rel="stylesheet" href="https://maxcdn.bootstrapcdn.com/bootstrap/3.3.7/css/bootstrap-theme.min.css" integrity="sha384-rHyoN1iRsVXV4nD0JutlnGaslCJuC7uwjduW9SVrLvRYooPp2bWYgmgJQIXwl/Sp" crossorigin="anonymous"/>
        <link rel="stylesheet" type="text/css" href="https://cdn.datatables.net/1.10.19/css/dataTables.bootstrap.min.css"/>
        <script src="https://code.jquery.com/jquery-3.3.1.js"></script>
        <script src="https://cdn.datatables.net/1.10.19/js/jquery.dataTables.min.js"></script>
        <script src="https://cdn.datatables.net/1.10.19/js/dataTables.bootstrap.min.js"></script>
        <script src="https://maxcdn.bootstrapcdn.com/bootstrap/3.3.7/js/bootstrap.min.js" integrity="sha384-Tc5IQib027qvyjSMfHjOMaLkfuWVxZxUPnCJA7l2mCWNIpG9mGCD8wGNIcPD7Txa" crossorigin="anonymous"></script>
        <style>
          .target:before {
            content: "";
            display: block;
            height: 50px;
            margin: -20px 0 0;
          }
          @media only screen and (min-width:1900px) {
            .container {
              width: 1800px;
              }
          }
          .footer {
            margin-top:60px;
            padding-top:60px;
            width: 100%;
            height: 180px;
            background-color: #f5f5f5;
          }
        </style>
        <title>Scan Report Nmap <xsl:value-of select="/nmaprun/@version"/></title>
      </head>
      <body>
        <nav class="navbar navbar-default navbar-fixed-top">
          <div class="container-fluid">
            <div class="navbar-header">
              <button type="button" class="navbar-toggle collapsed" data-toggle="collapse" data-target="#bs-example-navbar-collapse-1" aria-expanded="false">
                <span class="sr-only">Toggle navigation</span>
                <span class="icon-bar"></span>
                <span class="icon-bar"></span>
                <span class="icon-bar"></span>
              </button>
              <a class="navbar-brand" href="#"><span class="glyphicon glyphicon-home"></span></a>
            </div>
            <div class="collapse navbar-collapse" id="bs-example-navbar-collapse-1">
              <ul class="nav navbar-nav">
                <li><a href="#scannedhosts">Scanned Hosts</a></li>
                <li><a href="#onlinehosts">Online Hosts</a></li>
                <li><a href="#openservices">Open Services</a></li>
              </ul>
            </div>
          </div>
        </nav>
        <div class="container">
          <div class="jumbotron">
            <h1>Scan Report<br/><small>Nmap <xsl:value-of select="/nmaprun/@version"/></small></h1>
            <pre style="white-space:pre-wrap; word-wrap:break-word;"><xsl:value-of select="/nmaprun/@args"/></pre>
            <p class="lead">
              <xsl:value-of select="/nmaprun/@startstr"/> – <xsl:value-of select="/nmaprun/runstats/finished/@timestr"/><br/>
              <xsl:value-of select="/nmaprun/runstats/hosts/@total"/> hosts scanned.
              <xsl:value-of select="/nmaprun/runstats/hosts/@up"/> hosts up.
              <xsl:value-of select="/nmaprun/runstats/hosts/@down"/> hosts down.
            </p>
            <div class="progress">
              <div class="progress-bar progress-bar-success" style="width: 0%">
                <xsl:attribute name="style">width:<xsl:value-of select="/nmaprun/runstats/hosts/@up div /nmaprun/runstats/hosts/@total * 100"/>%;</xsl:attribute>
                <xsl:value-of select="/nmaprun/runstats/hosts/@up"/>
                <span class="sr-only"></span>
              </div>
              <div class="progress-bar progress-bar-danger" style="width: 0%">
                <xsl:attribute name="style">width:<xsl:value-of select="/nmaprun/runstats/hosts/@down div /nmaprun/runstats/hosts/@total * 100"/>%;</xsl:attribute>
                <xsl:value-of select="/nmaprun/runstats/hosts/@down"/>
                <span class="sr-only"></span>
              </div>
            </div>
          </div>
          <h2 id="scannedhosts" class="target">Scanned Hosts<xsl:if test="/nmaprun/runstats/hosts/@down > 1024"><small> (offline hosts are hidden)</small></xsl:if></h2>
          <div class="table-responsive">
            <table id="table-overview" class="table table-striped dataTable" role="grid">
              <thead>
                <tr>
                  <th>State</th>
                  <th>Address</th>
                  <th>Hostname</th>
                  <th>TCP (open)</th>
                  <th>UDP (open)</th>
                </tr>
              </thead>
              <tbody>
                <xsl:choose>
                  <xsl:when test="/nmaprun/runstats/hosts/@down > 1024">
                    <xsl:for-each select="/nmaprun/host[status/@state='up']">
                      <tr>
                        <td><span class="label label-danger"><xsl:if test="status/@state='up'"><xsl:attribute name="class">label label-success</xsl:attribute></xsl:if><xsl:value-of select="status/@state"/></span></td>
                        <td><xsl:value-of select="address/@addr"/></td>
                        <td><xsl:value-of select="hostnames/hostname/@name"/></td>
                        <td><xsl:value-of select="count(ports/port[state/@state='open' and @protocol='tcp'])"/></td>
                        <td><xsl:value-of select="count(ports/port[state/@state='open' and @protocol='udp'])"/></td>
                      </tr>
                    </xsl:for-each>
                  </xsl:when>
                  <xsl:otherwise>
                    <xsl:for-each select="/nmaprun/host">
                      <tr>
                        <td><span class="label label-danger"><xsl:if test="status/@state='up'"><xsl:attribute name="class">label label-success</xsl:attribute></xsl:if><xsl:value-of select="status/@state"/></span></td>
                        <td><xsl:value-of select="address/@addr"/></td>
                        <td><xsl:value-of select="hostnames/hostname/@name"/></td>
                        <td><xsl:value-of select="count(ports/port[state/@state='open' and @protocol='tcp'])"/></td>
                        <td><xsl:value-of select="count(ports/port[state/@state='open' and @protocol='udp'])"/></td>
                      </tr>
                    </xsl:for-each>
                  </xsl:otherwise>
                </xsl:choose>
              </tbody>
            </table>
          </div>
          <script>
            $(document).ready(function() {
              $('#table-overview').DataTable();
            });
          </script>
          <h2 id="onlinehosts" class="target">Online Hosts</h2>
          <xsl:for-each select="/nmaprun/host[status/@state='up']">
            <div class="panel panel-default">
              <div class="panel-heading">
                <h3 class="panel-title"><xsl:value-of select="address/@addr"/><xsl:if test="count(hostnames/hostname) > 0"> - <xsl:value-of select="hostnames/hostname/@name"/></xsl:if></h3>
              </div>
              <div class="panel-body">
                <xsl:if test="count(hostnames/hostname) > 0">
                  <h4>Hostnames</h4>
                  <ul>
                    <xsl:for-each select="hostnames/hostname">
                      <li><xsl:value-of select="@name"/> (<xsl:value-of select="@type"/>)</li>
                    </xsl:for-each>
                  </ul>
                </xsl:if>
                <h4>Ports</h4>
                <div class="table-responsive">
                  <table class="table table-bordered">
                    <thead>
                      <tr>
                        <th>Port</th>
                        <th>Protocol</th>
                        <th>State<br/>Reason</th>
                        <th>Service</th>
                        <th>Product</th>
                        <th>Version</th>
                        <th>Extra Info</th>
                      </tr>
                    </thead>
                    <tbody>
                      <xsl:for-each select="ports/port">
                        <xsl:choose>
                          <xsl:when test="state/@state = 'open'">
                            <tr class="success">
                              <td title="Port"><xsl:value-of select="@portid"/></td>
                              <td title="Protocol"><xsl:value-of select="@protocol"/></td>
                              <td title="State / Reason"><xsl:value-of select="state/@state"/><br/><xsl:value-of select="state/@reason"/></td>
                              <td title="Service"><xsl:value-of select="service/@name"/></td>
                              <td title="Product"><xsl:value-of select="service/@product"/></td>
                              <td title="Version"><xsl:value-of select="service/@version"/></td>
                              <td title="Extra Info"><xsl:value-of select="service/@extrainfo"/></td>
                            </tr>
                            <tr>
                              <td colspan="7">
                                <a><xsl:attribute name="href">https://nvd.nist.gov/vuln/search/results?form_type=Advanced&amp;cves=on&amp;cpe_version=<xsl:value-of select="service/cpe"/></xsl:attribute><xsl:value-of select="service/cpe"/></a>
                                <xsl:for-each select="script">
                                  <h5><xsl:value-of select="@id"/></h5>
                                  <pre style="white-space:pre-wrap; word-wrap:break-word;"><xsl:value-of select="@output"/></pre>
                                </xsl:for-each>
                              </td>
                            </tr>
                          </xsl:when>
                          <xsl:when test="state/@state = 'filtered'">
                            <tr class="warning">
                              <td><xsl:value-of select="@portid"/></td>
                              <td><xsl:value-of select="@protocol"/></td>
                              <td><xsl:value-of select="state/@state"/><br/><xsl:value-of select="state/@reason"/></td>
                              <td><xsl:value-of select="service/@name"/></td>
                              <td><xsl:value-of select="service/@product"/></td>
                              <td><xsl:value-of select="service/@version"/></td>
                              <td><xsl:value-of select="service/@extrainfo"/></td>
                            </tr>
                          </xsl:when>
                          <xsl:when test="state/@state = 'closed'">
                            <tr class="active">
                              <td><xsl:value-of select="@portid"/></td>
                              <td><xsl:value-of select="@protocol"/></td>
                              <td><xsl:value-of select="state/@state"/><br/><xsl:value-of select="state/@reason"/></td>
                              <td><xsl:value-of select="service/@name"/></td>
                              <td><xsl:value-of select="service/@product"/></td>
                              <td><xsl:value-of select="service/@version"/></td>
                              <td><xsl:value-of select="service/@extrainfo"/></td>
                            </tr>
                          </xsl:when>
                          <xsl:otherwise>
                            <tr class="info">
                              <td><xsl:value-of select="@portid"/></td>
                              <td><xsl:value-of select="@protocol"/></td>
                              <td><xsl:value-of select="state/@state"/><br/><xsl:value-of select="state/@reason"/></td>
                              <td><xsl:value-of select="service/@name"/></td>
                              <td><xsl:value-of select="service/@product"/></td>
                              <td><xsl:value-of select="service/@version"/></td>
                              <td><xsl:value-of select="service/@extrainfo"/></td>
                            </tr>
                          </xsl:otherwise>
                        </xsl:choose>
                      </xsl:for-each>
                    </tbody>
                  </table>
                </div>
                <xsl:if test="count(hostscript/script) > 0">
                  <h4>Host Script</h4>
                </xsl:if>
                <xsl:for-each select="hostscript/script">
                  <h5><xsl:value-of select="@id"/></h5>
                  <pre style="white-space:pre-wrap; word-wrap:break-word;"><xsl:value-of select="@output"/></pre>
                </xsl:for-each>
              </div>
            </div>
          </xsl:for-each>
          <h2 id="openservices" class="target">Open Services</h2>
          <div class="table-responsive">
            <table id="table-services" class="table table-striped dataTable" role="grid">
              <thead>
                <tr>
                  <th>Address</th>
                  <th>Port</th>
                  <th>Protocol</th>
                  <th>Service</th>
                  <th>Product</th>
                  <th>Version</th>
                  <th>CPE</th>
                  <th>Extra info</th>
                </tr>
              </thead>
              <tbody>
                <xsl:for-each select="/nmaprun/host">
                  <xsl:for-each select="ports/port[state/@state='open']">
                    <tr>
                      <td><xsl:value-of select="../../address/@addr"/><xsl:if test="count(../../hostnames/hostname) > 0"> - <xsl:value-of select="../../hostnames/hostname/@name"/></xsl:if></td>
                      <td><xsl:value-of select="@portid"/></td>
                      <td><xsl:value-of select="@protocol"/></td>
                      <td><xsl:value-of select="service/@name"/></td>
                      <td><xsl:value-of select="service/@product"/></td>
                      <td><xsl:value-of select="service/@version"/></td>
                      <td><xsl:value-of select="service/cpe"/></td>
                      <td><xsl:value-of select="service/@extrainfo"/></td>
                    </tr>
                  </xsl:for-each>
                </xsl:for-each>
              </tbody>
            </table>
          </div>
          <script>
            $(document).ready(function() {
              $('#table-services').DataTable();
            });
          </script>
        </div>
        <footer class="footer">
          <div class="container">
            <p class="text-muted">
              This report was generated with <a href="https://github.com/honze-net/nmap-bootstrap-xsl">Nmap Bootstrap XSL</a>.<br/>
              Licensed under <a href="https://creativecommons.org/licenses/by-sa/4.0/">Creative Commons BY-SA</a>.<br/>
              Designed and built by Andreas Hontzia (<a href="https://www.twitter.com/honze_net">@honze_net</a>).<br/>
            </p>
          </div>
        </footer>
      </body>
    </html>
  </xsl:template>
</xsl:stylesheet>
