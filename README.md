[![Sn1per](https://sn1persecurity.com/wordpress/wp-content/uploads/2026/04/sn1per-professional-2026-hero-banner.png)](https://sn1persecurity.com/wordpress/product/sn1per-professional-2026-license/)

[![GitHub release](https://img.shields.io/github/release/1N3/Sn1per.svg)](https://github.com/1N3/Sn1per/releases)
[![License](https://img.shields.io/github/license/1N3/Sn1per.svg)](https://github.com/1N3/Sn1per/blob/master/LICENSE.md)
[![GitHub issues](https://img.shields.io/github/issues/1N3/Sn1per.svg)](https://github.com/1N3/Sn1per/issues)
[![Last commit](https://img.shields.io/github/last-commit/1N3/Sn1per.svg)](https://github.com/1N3/Sn1per/commits/master)
[![Contributors](https://img.shields.io/github/contributors/1N3/Sn1per.svg)](https://github.com/1N3/Sn1per/graphs/contributors)

[![GitHub Stars](https://img.shields.io/github/stars/1N3/Sn1per.svg?style=social&label=Stars)](https://github.com/1N3/Sn1per/stargazers)
[![GitHub Forks](https://img.shields.io/github/forks/1N3/Sn1per.svg?style=social&label=Forks)](https://github.com/1N3/Sn1per/network/members)
[![GitHub Followers](https://img.shields.io/github/followers/1N3.svg?style=social&label=Follow)](https://github.com/1N3)
[![Follow on Twitter](https://img.shields.io/twitter/follow/xer0dayz.svg?style=social&label=Follow)](https://twitter.com/intent/follow?screen_name=xer0dayz)

[[Products](https://sn1persecurity.com/wordpress/shop/)] [[Attack Surface Management](https://sn1persecurity.com/wordpress/use-cases/)] [[About Sn1per](https://sn1persecurity.com/wordpress/about/)] [[News](https://sn1persecurity.com/wordpress/blog/)] [[Contact](https://sn1persecurity.com/wordpress/home/contact/)] [[Demo](https://sn1persecurity.com/wordpress/#video)] [[Pricing](https://sn1persecurity.com/wordpress/product/sn1per-professional-2026-license/)] [[Shop](https://sn1persecurity.com/wordpress/shop/)]

# Sn1per - The Offensive-Security Platform for Modern Teams

> Recon, scanning, exploitation, and reporting in a single workspace - whether you're a solo pentester or a global SOC.

> ## Sn1per Professional 2026 is here
>
> The largest release since v10.0 - Docker-first deployment, Bootstrap 5 / Tabler UI, Workspace Navigator, Workspace + Host Reports with CSV / Excel / PDF export, JSON API v1.0, an Offcanvas Quick Commands sidebar with 13 panels, and expanded modules for ReverseAPK, MassPwn, Threat Intel, Nessus, and Burp.
>
> [Read the release notes →](https://sn1persecurity.com/wordpress/sn1per-professional-2026-release/) · [View pricing →](https://sn1persecurity.com/wordpress/product/sn1per-professional-2026-license/)

## Table of Contents

- [About](#about-sn1per)
- [What Sn1per Is For](#what-sn1per-is-for)
- [What's New in 2026](#whats-new-in-2026)
- [Editions & Pricing](#editions--pricing)
- [Install](#install)
- [Quick Start](#quick-start)
- [Usage](#usage)
- [Scan Modes](#scan-modes)
- [Integrations](#integrations)
- [Use Sn1per from AI assistants (MCP)](#use-sn1per-from-ai-assistants-mcp)
- [Documentation & Help](#documentation--help)
- [News & Releases](#news--releases)
- [Community & Support](#community--support)
- [Contributing](#contributing)
- [License & Legal](#license--legal)

## About Sn1per

Sn1per is an offensive-security platform that consolidates reconnaissance, vulnerability scanning, exploitation, and reporting into a single workspace. Built by pentesters since 2015, it ships in three editions - a free Community Edition (source-available, custom EULA - see LICENSE.md) in this repository, a paid Professional edition for individual operators and small teams, and an Enterprise edition for global SOCs - all backed by the same core scanning engine.

Sn1per orchestrates 90+ third-party tools, ships with 600+ exploits and 10,000+ detections, and is used by 500+ teams worldwide. Battle-tested by the community. Built by pentesters, for pentesters.

**500+** Teams · **90+** Integrations · **10,000+** Detections · **600+** Exploits · Trusted since **2015**

## What Sn1per Is For

Sn1per ships as one platform that covers the core jobs offensive security teams otherwise stitch together from a dozen tools:

- **[External Attack Surface Management](https://sn1persecurity.com/wordpress/external-attack-surface-management-with-sn1per/)** - continuous discovery, monitoring, and active exploitation of every internet-facing asset your organization owns, including the ones nobody on your team knows about.
- **[Continuous Attack Surface Management](https://sn1persecurity.com/wordpress/continuous-attack-surface-management-with-sn1per-professional/)** - daily-cadence rescans that diff yesterday's surface against today's so new exposures hit your SOC within hours, not the next quarterly pentest.
- **[Automated Penetration Testing](https://sn1persecurity.com/wordpress/automated-penetration-testing/)** - 600+ exploits and 10,000+ detections orchestrated as a single workflow, with active verification eliminating the false positives version-only scanners ship as "critical."
- **[Reconnaissance & Attack Surface Discovery](https://sn1persecurity.com/wordpress/reconnaissance-methodology/)** - the full phased recon workflow, from OSINT and subdomain enumeration through live-host discovery and fingerprinting, run as one automated pass.

## What's New in 2026

> **New (October 2026):** the [Sn1per MCP Server](https://sn1persecurity.com/wordpress/sn1per-mcp-server/) (beta) lets AI assistants like Claude Code launch Sn1per scans and read the results. [Details below](#use-sn1per-from-ai-assistants-mcp).

[![Sn1per Pro 2026 Workspace Navigator](https://sn1persecurity.com/wordpress/wp-content/uploads/2026/04/sn1per-pro-2026-workspace-navigator.png)](https://sn1persecurity.com/wordpress/sn1per-professional-2026-release/)

*Workspace Navigator - switch contexts across hosts, scopes, and engagements.*

[![Sn1per Pro 2026 Dashboard](https://sn1persecurity.com/wordpress/wp-content/uploads/2026/04/sn1per-pro-2026-dashboard.png)](https://sn1persecurity.com/wordpress/sn1per-professional-2026-release/)

*Dashboard - at-a-glance scan posture, top findings, and exploitable assets.*

### Highlights

- **Docker-first deployment** - same image, every distro
- **Bootstrap 5 / Tabler UI** - refreshed responsive interface with light + dark mode
- **Workspace Navigator** - fast workspace switching with state preservation
- **Workspace & Host Reports** - CSV, Excel, and PDF export
- **JSON API v1.0** - programmatic access for CI / SOAR / SIEM pipelines
- **Offcanvas Quick Commands** - 13 panels, every common action one click away
- **Expanded modules** - ReverseAPK, MassPwn, Threat Intel, Nessus, Burp Suite
- **Maturing SC0PE framework** - more parsers, better noise reduction
- **Hardened PHP library stack** - modern dependencies, audited components
- **New CLI flags** - `-v` (verbose), `-db` (debug), `-rr` (remove resume files)

> *"Sn1per Professional 2026 is the largest release since the v10.0 line."*

[Read the full release notes →](https://sn1persecurity.com/wordpress/sn1per-professional-2026-release/)

## Editions & Pricing

The [Community Edition](https://sn1persecurity.com/wordpress/sn1per-community-edition/) is free and lives in this repository. The Professional and Enterprise editions add a Web UI, commercial integrations, and email support.

| | **Sn1per Professional** | **Sn1per Enterprise** |
|---|---|---|
| **Price** | $984 / year (per seat) | Get a quote |
| **Subscription** | 1 year | 1 year |
| **- Included -** | | |
| Web UI | Professional Web UI | Enterprise Web UI |
| Scan Engine & UI Updates | ✓ | ✓ |
| All Modules & Integrations | ✓ | ✓ |
| On-Prem (Self Hosted) | ✓ | ✓ |
| Email Support | 1 Year | 1 Year |
| Improved Speed & Scalability | - | ✓ |
| Cutting-Edge Features | - | ✓ |
| **- Limits & Quotas -** | | |
| Max Scans | Unlimited | Unlimited |
| Max Assets / Workspace | 30 | Unlimited |
| Max Workspaces | 5 | Unlimited |
| Total Assets | 150 | 500+ |
| Licensed Systems | 1 | 1 |

[Buy a Sn1per Professional license →](https://sn1persecurity.com/wordpress/product/sn1per-professional-2026-license/) · [Get an Enterprise quote →](https://sn1persecurity.com/wordpress/request-a-quote/)

## Install

### Linux (Kali / Ubuntu / Debian / Parrot)

```bash
git clone https://github.com/1N3/Sn1per.git
cd Sn1per
sudo bash install.sh
```

> Sn1per installs to `/usr/share/sniper` and requires root. Use `sudo bash install.sh force` to skip the confirmation prompt.

### Docker

[Sn1per on Docker Hub →](https://hub.docker.com/r/sn1persecurity/sn1per)

#### Kali Linux base

```bash
sudo docker compose up
sudo docker run --privileged -it sn1per-kali-linux /bin/bash
```

#### BlackArch base

```bash
sudo docker compose -f docker-compose-blackarch.yml up
sudo docker run --privileged -it sn1per-blackarch /bin/bash
```

### AWS Marketplace (EC2 AMI)

Subscribe via [AWS Marketplace](https://aws.amazon.com/marketplace/pp/prodview-rmloab6wnymno):

1. Click **Continue to Subscribe**
2. Click **Continue to Configuration**, choose region/instance type
3. Click **Continue to Launch**
4. SSH to the EC2 public IP - Sn1per is preinstalled

## Quick Start

```bash
sudo bash install.sh
sniper -t example.com -m normal
```

Results land in `/usr/share/sniper/loot/<workspace>/`. See [Usage](#usage) for more modes.

## Usage

```
[*] NORMAL MODE
sniper -t <TARGET>

[*] NORMAL MODE + OSINT + RECON
sniper -t <TARGET> -o -re

[*] STEALTH MODE + OSINT + RECON
sniper -t <TARGET> -m stealth -o -re

[*] DISCOVER MODE
sniper -t <CIDR> -m discover -w <WORKSPACE_ALIAS>

[*] SCAN ONLY SPECIFIC PORT
sniper -t <TARGET> -m port -p <portnum>

[*] FULLPORTONLY SCAN MODE
sniper -t <TARGET> -fp

[*] WEB MODE - PORT 80 + 443 ONLY!
sniper -t <TARGET> -m web

[*] HTTP WEB PORT MODE
sniper -t <TARGET> -m webporthttp -p <port>

[*] HTTPS WEB PORT MODE
sniper -t <TARGET> -m webporthttps -p <port>

[*] HTTP WEBSCAN MODE
sniper -t <TARGET> -m webscan

[*] ENABLE BRUTEFORCE
sniper -t <TARGET> -b

[*] AIRSTRIKE MODE
sniper -f targets.txt -m airstrike

[*] NUKE MODE WITH TARGET LIST, BRUTEFORCE ENABLED, FULLPORTSCAN ENABLED, OSINT ENABLED, RECON ENABLED, WORKSPACE & LOOT ENABLED
sniper -f targets.txt -m nuke -w <WORKSPACE_ALIAS>

[*] MASS PORT SCAN MODE
sniper -f targets.txt -m massportscan

[*] MASS WEB SCAN MODE
sniper -f targets.txt -m massweb

[*] MASS WEBSCAN SCAN MODE
sniper -f targets.txt -m masswebscan

[*] MASS VULN SCAN MODE
sniper -f targets.txt -m massvulnscan

[*] PORT SCAN MODE
sniper -t <TARGET> -m port -p <PORT_NUM>

[*] LIST WORKSPACES
sniper --list

[*] DELETE WORKSPACE
sniper -w <WORKSPACE_ALIAS> -d

[*] DELETE HOST FROM WORKSPACE
sniper -w <WORKSPACE_ALIAS> -t <TARGET> -dh

[*] GET SNIPER SCAN STATUS
sniper --status

[*] LOOT REIMPORT FUNCTION
sniper -w <WORKSPACE_ALIAS> --reimport

[*] LOOT REIMPORTALL FUNCTION
sniper -w <WORKSPACE_ALIAS> --reimportall

[*] LOOT RELOAD FUNCTION
sniper -w <WORKSPACE_ALIAS> --reload

[*] LOOT EXPORT FUNCTION
sniper -w <WORKSPACE_ALIAS> --export

[*] SCHEDULED SCANS
sniper -w <WORKSPACE_ALIAS> -s daily|weekly|monthly

[*] USE A CUSTOM CONFIG
sniper -c /path/to/sniper.conf -t <TARGET> -w <WORKSPACE_ALIAS>

[*] UPDATE SNIPER
sniper -u|--update

[*] VERBOSE OUTPUT (NEW IN 2026)
sniper -t <TARGET> -m airstrike -v

[*] DEBUG OUTPUT (NEW IN 2026)
sniper -t <TARGET> -m normal -db

[*] REMOVE RESUME FILES (NEW IN 2026)
sniper -t <TARGET> -m airstrike -v -rr
```

## Scan Modes

| Mode | Description |
|------|-------------|
| `normal` | Active + passive scan of the target and its open ports |
| `stealth` | Quick, mostly non-intrusive enumeration to avoid WAF / IPS |
| `flyover` | Fast multi-threaded high-level scans of many hosts |
| `airstrike` | Open-port enumeration + basic fingerprinting against a host file |
| `nuke` | Full audit across all targets in a host file |
| `discover` | Walks a CIDR and runs Sn1per on every live host |
| `port` | Targeted scan of a specific port |
| `fullportonly` | Full TCP port scan, results saved to XML |
| `web` | Web app scan on `80/tcp` + `443/tcp` only |
| `webporthttp` / `webporthttps` | Web app scan on a specific HTTP / HTTPS port |
| `webscan` | Full HTTP + HTTPS web app scan via Burp Suite + Arachni |
| `vulnscan` | OpenVAS vulnerability scan |
| `mass*` | Multi-target variants of the above (`-f targets.txt`) |

## Integrations

Sn1per ships with native integrations for **90+ tools and services**. Featured partners:

| Category | Integrations |
|----------|--------------|
| **Vulnerability scanners** | [Nessus](https://github.com/1N3/Sn1per/wiki/Nessus-Integration) · [OpenVAS](https://github.com/1N3/Sn1per/wiki/OpenVAS-Integration) · [GVM 21.x](https://github.com/1N3/Sn1per/wiki/GVM-21.x-Integration) · Nuclei |
| **Web app testing** | [Burp Suite Pro](https://github.com/1N3/Sn1per/wiki/Burpsuite-Professional-2.x-Integration) · [OWASP ZAP](https://github.com/1N3/Sn1per/wiki/OWASP-ZAP-Integration) · [WPScan](https://github.com/1N3/Sn1per/wiki/WPScan-API-Integration) |
| **Exploitation** | [Metasploit](https://github.com/1N3/Sn1per/wiki/Metasploit-Integration) |
| **Reconnaissance** | [Shodan](https://github.com/1N3/Sn1per/wiki/Shodan-Integration) · [Censys](https://github.com/1N3/Sn1per/wiki/Censys-API-Integration) · [Hunter.io](https://github.com/1N3/Sn1per/wiki/Hunter.io-API-Integration) · VirusTotal · Nmap |
| **AI / LLM** | OpenAI · Claude · Gemini |
| **AI assistants (MCP)** | [Sn1per MCP Server](https://github.com/1N3/sn1per-mcp) - drive Sn1per from Claude Code, Codex CLI, and other MCP clients |
| **Notifications & DevOps** | [Slack](https://github.com/1N3/Sn1per/wiki/Slack-API-Integration) · [GitHub API](https://github.com/1N3/Sn1per/wiki/Github-API-Integration) |

[Browse all integrations on the wiki →](https://github.com/1N3/Sn1per/wiki)

## Use Sn1per from AI assistants (MCP)

Sn1per does the scanning. The [Sn1per MCP Server](https://github.com/1N3/sn1per-mcp) (beta) lets the AI assistant you already use drive it. It is a [Model Context Protocol](https://modelcontextprotocol.io/) server that runs locally over stdio beside your Sn1per installation. It:

- refuses scan requests for targets outside the scope you configure;
- records every scan, cancel, delete and export request in a local audit log;
- returns Sn1per's findings, open ports, subdomains and technologies as structured data, with secrets redacted by default;
- keeps brute-force, exploitation and destructive tools off by default.

It supports Sn1per Community Edition 9.x and the 11.x engine used by SE, Professional and Enterprise. The MCP server is free and open source (Apache-2.0) and installs from [PyPI](https://pypi.org/project/sn1per-mcp/) with `pipx install sn1per-mcp`.

- [Sn1per MCP Server Beta: Drive Sn1per From Your AI Assistant](https://sn1persecurity.com/wordpress/sn1per-mcp-server/) - launch post: what it does, how it works, and an example session
- [Sn1per MCP Server documentation](https://sn1persecurity.com/wordpress/documentation/mcp/) - install, scope, sudo, and client setup
- [sn1per-mcp on GitHub](https://github.com/1N3/sn1per-mcp) - source, quick start, security model, and edition matrix

Example prompt, once a target you are authorized to test is in the server's scope:

```text
Run sniper_status. Then start a stealth scan of app.example, check scan_status until it finishes, and summarize the open ports, technologies and findings.
```

> For authorized security testing only. Use the Sn1per MCP Server only against systems you own or are explicitly permitted, in writing, to test.

## Documentation & Help

- [Getting Started](docs/getting-started.md)
- [Installation](docs/installation.md)
- [Configuration](docs/configuration.md)
- [Usage](docs/usage.md)
- [Architecture](docs/architecture.md)
- [Integrations](docs/integrations.md)
- [Troubleshooting](docs/troubleshooting.md)
- [Sn1per MCP Server documentation](https://sn1persecurity.com/wordpress/documentation/mcp/)
- [Wiki - full reference](https://github.com/1N3/Sn1per/wiki)
- [Sn1per Documentation Hub](https://sn1persecurity.com/wordpress/documentation/)
- [Passive Reconnaissance Techniques for Penetration Testers](https://sn1persecurity.com/wordpress/passive-reconnaissance-techniques-for-penetration-testing/)
- [CVE-2024-21733 - Apache Tomcat HTTP Request Smuggling writeup](https://sn1persecurity.com/wordpress/cve-2024-21733-apache-tomcat-http-request-smuggling/)

### Configuration & Templates

- [Plugins & Tools](https://github.com/1N3/Sn1per/wiki/Plugins-&-Tools)
- [Scheduled Scans](https://github.com/1N3/Sn1per/wiki/Scheduled-Scans)
- [Sn1per Configuration Options](https://github.com/1N3/Sn1per/wiki/Sn1per-Configuration-Options)
- [Sn1per Configuration Templates](https://github.com/1N3/Sn1per/wiki/Sn1per-Configuration-Templates)
- [Sc0pe Templates](https://github.com/1N3/Sn1per/wiki/Sc0pe-Templates)

## News & Releases

- **[Sn1per MCP Server Beta: Drive Sn1per From Your AI Assistant](https://sn1persecurity.com/wordpress/sn1per-mcp-server/)** - October 18, 2026
- **[Sn1per Professional 2026 Released](https://sn1persecurity.com/wordpress/sn1per-professional-2026-release/)** - April 26, 2026
- [Introducing SILENTCHAIN AI Community Edition v1.1.3](https://sn1persecurity.com/wordpress/introducing-silentchain-ai-community-edition-v1-1-3/) - February 11, 2026
- [Sn1per SE v11.0 Now Available](https://sn1persecurity.com/wordpress/sn1per-se-v11-released/) - January 8, 2026

### Guides & deep dives (2026)

**Reconnaissance**

- [Reconnaissance Methodology](https://sn1persecurity.com/wordpress/reconnaissance-methodology/) - Sn1per's full recon-to-report workflow, phase by phase, from OSINT to reporting
- [Subdomain Enumeration](https://sn1persecurity.com/wordpress/subdomain-enumeration/) - passive sources, active brute force, and subdomain-takeover checks
- [Active Reconnaissance](https://sn1persecurity.com/wordpress/active-reconnaissance/) - port scanning, service and technology fingerprinting, and endpoint discovery

**Penetration testing**

- [Automated Penetration Testing](https://sn1persecurity.com/wordpress/automated-penetration-testing/) - the method, the tooling, and the continuous-testing model
- [Best Automated Pentest Tools](https://sn1persecurity.com/wordpress/automated-pentest-tools/) - the 2026 open-source and all-in-one pentest tooling landscape
- [Continuous Penetration Testing (PTaaS)](https://sn1persecurity.com/wordpress/continuous-penetration-testing/) - the always-on model beyond the once-a-year pentest

**Attack surface management**

- [Red Team Attack Surface Management](https://sn1persecurity.com/wordpress/red-team-attack-surface-management/) - running Sn1per as a continuous red-team and adversarial-exposure-validation workflow
- [Adversarial Exposure Validation](https://sn1persecurity.com/wordpress/adversarial-exposure-validation/) - proving which exposures are actually exploitable, not just present
- [Continuous Attack Surface Testing](https://sn1persecurity.com/wordpress/continuous-attack-surface-testing/) - daily-cadence rescans that diff yesterday's surface against today's
- [On-Prem External Attack Surface Management](https://sn1persecurity.com/wordpress/best-on-prem-external-attack-surface-management-platform/) - self-hosted, air-gapped ASM with zero data leaving your perimeter
- [Open-Source Self-Hosted ASM Tools](https://sn1persecurity.com/wordpress/open-source-self-hosted-attack-surface-management-tools/) - the self-hosted attack surface management tooling landscape
- [External Attack Surface Management with Sn1per](https://sn1persecurity.com/wordpress/external-attack-surface-management-with-sn1per/) - background reading on the ASM use case

[All releases & blog posts →](https://sn1persecurity.com/wordpress/blog/)

## Community & Support

- **Bugs:** [Open an issue](https://github.com/1N3/Sn1per/issues)
- **Twitter:** [@xer0dayz](https://twitter.com/xer0dayz)
- **YouTube:** [Sn1per Security](https://www.youtube.com/c/Sn1perSecurity/videos) - latest demo: [Continuous Attack Surface Testing](https://youtu.be/GBr7vjbGRBA)
- **Email (Pro / Enterprise customers):** see your license email

## Contributing

Pull requests welcome. For substantial changes, open an issue first to discuss the design.

- Mode scripts live in [`modes/`](modes/) - one bash file per scan mode
- Test changes against a controlled target before opening a PR
- Follow [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) format in [`CHANGELOG.md`](CHANGELOG.md)

35 contributors and counting. Thank you.

## License & Legal

- **Code:** see [`LICENSE.md`](LICENSE.md) and [`THIRD_PARTY_LICENSES.md`](THIRD_PARTY_LICENSES.md)
- **Notices:** see [`NOTICE`](NOTICE)
- **Trademark:** "Sn1per" and the Sn1per logo are trademarks of Sn1perSecurity LLC. Use in derivative works requires permission. Contact: [sn1persecurity.com](https://sn1persecurity.com)

---

## About Sn1perSecurity

Sn1per is built and maintained by [Sn1perSecurity](https://sn1persecurity.com), the team behind the [Sn1per attack surface management and automated penetration testing platform](https://sn1persecurity.com/wordpress/external-attack-surface-management-with-sn1per/). Small team of pentesters shipping offensive-security tooling since 2015. We focus on the workflows we want to use ourselves - fast recon, ergonomic reporting, honest pricing, and a Community Edition that genuinely keeps up with the commercial editions. If that resonates, [say hi](https://twitter.com/xer0dayz).

**Topics:** `penetration-testing` · `offensive-security` · `attack-surface-management` · `vulnerability-scanner` · `recon` · `osint` · `red-team` · `bug-bounty` · `security-tools`
