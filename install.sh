#!/bin/bash
# Cross-platform install script for Sn1per CE
# Supports: Debian/Ubuntu, RHEL/CentOS/Fedora/Amazon Linux, Arch Linux, macOS
# Created by @xer0dayz - https://sn1persecurity.com
# Optimized by D4rth R3v4n - https://github.com/gbiagomba
# Optimized for multi-distro support

set -e  # Exit on error

# Color definitions
OKBLUE='\033[94m'
OKRED='\033[91m'
OKGREEN='\033[92m'
OKORANGE='\033[93m'
RESET='\e[0m'

# Banner
echo -e "$OKRED                ____               $RESET"
echo -e "$OKRED    _________  /  _/___  ___  _____$RESET"
echo -e "$OKRED   / ___/ __ \ / // __ \/ _ \/ ___/$RESET"
echo -e "$OKRED  (__  ) / / // // /_/ /  __/ /    $RESET"
echo -e "$OKRED /____/_/ /_/___/ .___/\___/_/     $RESET"
echo -e "$OKRED               /_/                 $RESET"
echo -e "$RESET"
echo -e "$OKORANGE + -- --=[ https://sn1persecurity.com $RESET"
echo -e "$OKORANGE + -- --=[ Sn1per CE by @xer0dayz $RESET"
echo -e "$OKORANGE + -- --=[ Multi-distro installer $RESET"
echo ""

# Installation directories
INSTALL_DIR=/usr/share/sniper
LOOT_DIR=/usr/share/sniper/loot
PLUGINS_DIR=/usr/share/sniper/plugins
GO_DIR=~/go/bin

# Detect OS and distribution
detect_os() {
    if [[ "$OSTYPE" == "darwin"* ]]; then
        OS="macos"
        echo -e "$OKBLUE[*]$RESET Detected macOS"
    elif [[ -f /etc/os-release ]]; then
        . /etc/os-release
        case "$ID" in
            ubuntu|debian|kali|parrot)
                OS="debian"
                PKG_MANAGER="apt"
                echo -e "$OKBLUE[*]$RESET Detected Debian-based system: $PRETTY_NAME"
                ;;
            rhel|centos|fedora|rocky|alma|amzn)
                OS="rhel"
                if command -v dnf &> /dev/null; then
                    PKG_MANAGER="dnf"
                else
                    PKG_MANAGER="yum"
                fi
                echo -e "$OKBLUE[*]$RESET Detected RHEL-based system: $PRETTY_NAME"
                ;;
            arch|manjaro|endeavouros)
                OS="arch"
                PKG_MANAGER="pacman"
                echo -e "$OKBLUE[*]$RESET Detected Arch-based system: $PRETTY_NAME"
                ;;
            opensuse*|sles)
                OS="opensuse"
                PKG_MANAGER="zypper"
                echo -e "$OKBLUE[*]$RESET Detected openSUSE-based system: $PRETTY_NAME"
                ;;
            *)
                echo -e "$OKRED[!]$RESET Unsupported distribution: $ID"
                echo -e "$OKRED[!]$RESET Supported: Debian/Ubuntu, RHEL/CentOS/Fedora, Arch Linux, macOS"
                exit 1
                ;;
        esac
    else
        echo -e "$OKRED[!]$RESET Unable to detect operating system"
        exit 1
    fi
}

# Check if running as root (not needed for macOS with brew)
check_root() {
    if [[ "$OS" != "macos" ]] && [[ $EUID -ne 0 ]]; then
        echo -e "$OKRED[!]$RESET This script must be run as root on Linux systems"
        echo -e "$OKRED[!]$RESET Please run: sudo $0"
        exit 1
    fi
}

# Package manager abstraction
pkg_update() {
    echo -e "$OKBLUE[*]$RESET Updating package repositories..."
    case "$OS" in
        debian)
            apt update -y
            ;;
        rhel)
            $PKG_MANAGER makecache -y || $PKG_MANAGER makecache
            ;;
        arch)
            pacman -Sy --noconfirm
            ;;
        opensuse)
            zypper refresh -y
            ;;
        macos)
            brew update
            ;;
    esac
}

pkg_install() {
    local packages=("$@")
    echo -e "$OKBLUE[*]$RESET Installing: ${packages[*]}"
    
    case "$OS" in
        debian)
            apt install -y "${packages[@]}" 2>/dev/null || true
            ;;
        rhel)
            $PKG_MANAGER install -y "${packages[@]}" 2>/dev/null || true
            ;;
        arch)
            pacman -S --noconfirm --needed "${packages[@]}" 2>/dev/null || true
            ;;
        opensuse)
            zypper install -y "${packages[@]}" 2>/dev/null || true
            ;;
        macos)
            for pkg in "${packages[@]}"; do
                brew install "$pkg" 2>/dev/null || brew upgrade "$pkg" 2>/dev/null || true
            done
            ;;
    esac
}

# Map package names across distributions
get_package_name() {
    local generic_name=$1
    
    case "$OS" in
        debian)
            case "$generic_name" in
                python) echo "python3" ;;
                pip) echo "python3-pip" ;;
                ruby-dev) echo "ruby-dev" ;;
                *) echo "$generic_name" ;;
            esac
            ;;
        rhel)
            case "$generic_name" in
                python) echo "python3" ;;
                pip) echo "python3-pip" ;;
                ruby-dev) echo "ruby-devel" ;;
                libssl-dev) echo "openssl-devel" ;;
                build-essential) echo "gcc gcc-c++ make" ;;
                *) echo "$generic_name" ;;
            esac
            ;;
        arch)
            case "$generic_name" in
                python) echo "python" ;;
                pip) echo "python-pip" ;;
                ruby-dev) echo "ruby" ;;
                libssl-dev) echo "openssl" ;;
                build-essential) echo "base-devel" ;;
                *) echo "$generic_name" ;;
            esac
            ;;
        macos)
            case "$generic_name" in
                python) echo "python@3" ;;
                pip) echo "" ;; # comes with python
                ruby-dev) echo "ruby" ;;
                libssl-dev) echo "openssl" ;;
                build-essential) echo "" ;; # xcode tools
                *) echo "$generic_name" ;;
            esac
            ;;
    esac
}

# Install build tools
install_build_tools() {
    echo -e "$OKBLUE[*]$RESET Installing build tools..."
    
    case "$OS" in
        debian)
            pkg_install build-essential git curl wget
            ;;
        rhel)
            pkg_install gcc gcc-c++ make git curl wget
            if [[ "$PKG_MANAGER" == "dnf" ]]; then
                $PKG_MANAGER groupinstall -y "Development Tools" 2>/dev/null || true
            else
                $PKG_MANAGER groupinstall -y "Development Tools" 2>/dev/null || true
            fi
            ;;
        arch)
            pkg_install base-devel git curl wget
            ;;
        opensuse)
            pkg_install -t pattern devel_basis
            pkg_install git curl wget
            ;;
        macos)
            # Check for Xcode Command Line Tools
            if ! xcode-select -p &>/dev/null; then
                echo -e "$OKBLUE[*]$RESET Installing Xcode Command Line Tools..."
                xcode-select --install 2>/dev/null || true
            fi
            pkg_install git curl wget
            ;;
    esac
}

# Install base dependencies
install_base_dependencies() {
    echo -e "$OKBLUE[*]$RESET Installing base dependencies..."
    
    local base_pkgs=()
    
    case "$OS" in
        debian)
            base_pkgs=(
                sudo gpg curl wget git
                nmap nikto sqlmap hydra
                whois dnsutils dnsrecon
                ruby rubygems ruby-dev
                python3 python3-pip python3-paramiko
                golang
                nodejs npm
                php php-curl
                dos2unix aha jq xmlstarlet
                libxml2-utils xsltproc
                net-tools iputils-ping
                nfs-common rpcbind
                nbtscan enum4linux
                whatweb wafw00f sslscan
                xdg-utils xvfb
                p7zip-full
                libssl-dev
            )
            
            # Optional packages
            pkg_install theharvester 2>/dev/null || true
            pkg_install urlcrazy 2>/dev/null || true
            
            # Install chromium
            if [[ "$ID" == "ubuntu" ]]; then
                snap install chromium 2>/dev/null || apt install -y chromium-browser 2>/dev/null || true
            else
                pkg_install chromium 2>/dev/null || pkg_install chromium-browser 2>/dev/null || true
            fi
            ;;
            
        rhel)
            # Enable EPEL for RHEL-based systems
            if [[ "$ID" == "rhel" ]] || [[ "$ID" == "centos" ]] || [[ "$ID" == "rocky" ]] || [[ "$ID" == "alma" ]]; then
                $PKG_MANAGER install -y epel-release 2>/dev/null || true
            fi
            
            base_pkgs=(
                sudo git curl wget
                nmap
                whois bind-utils
                ruby ruby-devel rubygems
                python3 python3-pip
                golang
                nodejs npm
                php php-curl
                jq
                libxml2 libxslt
                net-tools iputils
                rpcbind
                openssl openssl-devel
                p7zip p7zip-plugins
                xorg-x11-server-Xvfb
            )
            
            # Try to install additional tools (may not be available)
            pkg_install nikto sqlmap hydra 2>/dev/null || true
            ;;
            
        arch)
            base_pkgs=(
                sudo git curl wget
                nmap nikto sqlmap hydra
                whois dnsutils
                ruby rubygems
                python python-pip python-paramiko
                go
                nodejs npm
                php
                dos2unix jq xmlstarlet
                libxml2 libxslt
                net-tools iputils
                nfs-utils rpcbind
                sslscan
                xorg-xauth xorg-server-xvfb
                p7zip
                openssl
            )
            ;;
            
        macos)
            base_pkgs=(
                git curl wget
                nmap
                ruby
                python@3
                go
                node
                php
                jq
                libxml2 libxslt
                p7zip
                openssl
            )
            
            # Some tools may need cask
            brew install --cask chromium 2>/dev/null || true
            ;;
    esac
    
    pkg_install "${base_pkgs[@]}"
}

# Setup Python environment
setup_python() {
    echo -e "$OKBLUE[*]$RESET Setting up Python environment..."
    
    # Upgrade pip
    python3 -m pip install --upgrade pip --break-system-packages 2>/dev/null || \
        python3 -m pip install --upgrade pip 2>/dev/null || true
    
    # Install Python packages
    local py_packages=(
        dnspython
        colorama
        tldextract
        urllib3
        ipaddress
        requests
        h8mail
        webtech
    )
    
    for pkg in "${py_packages[@]}"; do
        pip3 install "$pkg" --break-system-packages 2>/dev/null || \
            pip3 install "$pkg" 2>/dev/null || true
    done
}

# Setup Ruby environment
setup_ruby() {
    echo -e "$OKBLUE[*]$RESET Setting up Ruby environment..."
    
    local ruby_gems=(
        rake
        ruby-nmap
        net-http-persistent
        mechanize
        text-table
        public_suffix
    )
    
    for gem in "${ruby_gems[@]}"; do
        gem install "$gem" 2>/dev/null || true
    done
    
    # Reconfigure ruby (Debian-specific)
    if [[ "$OS" == "debian" ]]; then
        dpkg-reconfigure ruby 2>/dev/null || true
    fi
}

# Setup Go environment
setup_go() {
    echo -e "$OKBLUE[*]$RESET Setting up Go environment..."
    
    # Ensure Go is in PATH
    export PATH=$PATH:/usr/local/go/bin:$HOME/go/bin
    export GOPATH=$HOME/go
    
    # Create Go bin directory
    mkdir -p "$GO_DIR" 2>/dev/null || true
    
    # Update Go (if needed)
    go version 2>/dev/null || {
        echo -e "$OKRED[!]$RESET Go is not properly installed"
        return 1
    }
}

# Install Metasploit
install_metasploit() {
    echo -e "$OKBLUE[*]$RESET Installing Metasploit Framework..."
    
    case "$OS" in
        debian|rhel)
            # Use official installer
            if ! command -v msfconsole &>/dev/null; then
                curl https://raw.githubusercontent.com/rapid7/metasploit-omnibus/master/config/templates/metasploit-framework-wrappers/msfupdate.erb > /tmp/msfinstall
                chmod 755 /tmp/msfinstall
                /tmp/msfinstall 2>/dev/null || echo -e "$OKORANGE[!]$RESET Metasploit installation failed (optional)"
                rm -f /tmp/msfinstall
            fi
            ;;
        arch)
            pkg_install metasploit 2>/dev/null || true
            ;;
        macos)
            brew install metasploit 2>/dev/null || true
            ;;
    esac
    
    # Initialize database
    if command -v msfdb &>/dev/null; then
        msfdb init 2>/dev/null || true
    fi
}

# Create directory structure
create_directories() {
    echo -e "$OKBLUE[*]$RESET Creating directory structure..."
    
    local dirs=(
        "$INSTALL_DIR"
        "$LOOT_DIR"
        "$LOOT_DIR/domains"
        "$LOOT_DIR/screenshots"
        "$LOOT_DIR/nmap"
        "$LOOT_DIR/reports"
        "$LOOT_DIR/output"
        "$LOOT_DIR/osint"
        "$LOOT_DIR/workspaces"
        "$PLUGINS_DIR"
        "$GO_DIR"
    )
    
    for dir in "${dirs[@]}"; do
        mkdir -p "$dir" 2>/dev/null || true
    done
    
    # Set permissions
    if [[ "$OS" != "macos" ]]; then
        chmod 755 -Rf "$INSTALL_DIR" 2>/dev/null || true
        chown -R root:root "$INSTALL_DIR" 2>/dev/null || true
    fi
}

# Install Sn1per files
install_sniper_files() {
    echo -e "$OKBLUE[*]$RESET Installing Sn1per files..."
    
    # Copy all files to install directory
    cp -Rf ./* "$INSTALL_DIR/" 2>/dev/null || true
    
    # Make main script executable
    chmod +x "$INSTALL_DIR/sniper" 2>/dev/null || true
}

# Install Go-based tools
install_go_tools() {
    echo -e "$OKBLUE[*]$RESET Installing Go-based tools..."
    
    cd "$GO_DIR" || return
    
    local go_tools=(
        "github.com/projectdiscovery/nuclei/v2/cmd/nuclei@latest:nuclei"
        "github.com/haccer/subjack@latest:subjack"
        "github.com/Ice3man543/SubOver@latest:subover"
        "github.com/theblackturtle/fprobe@latest:fprobe"
        "github.com/harleo/asnip@latest:asnip"
        "github.com/lc/gau@latest:gau"
        "github.com/projectdiscovery/httpx@latest:httpx"
        "github.com/ffuf/ffuf@latest:ffuf"
        "github.com/gwen001/github-endpoints@latest:github-endpoints"
        "github.com/d3mondev/puredns/v2@latest:puredns"
        "github.com/OWASP/Amass/v3/...@master:amass"
        "github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest:subfinder"
        "github.com/1N3/dirdar@latest:dirdar"
    )
    
    for tool_info in "${go_tools[@]}"; do
        IFS=':' read -r tool_path tool_name <<< "$tool_info"
        echo -e "$OKBLUE[*]$RESET Installing $tool_name..."
        
        GO111MODULE=on go install -v "$tool_path" 2>/dev/null || true
        
        # Create symlink
        if [[ -f "$HOME/go/bin/$tool_name" ]]; then
            ln -fs "$HOME/go/bin/$tool_name" /usr/local/bin/"$tool_name" 2>/dev/null || \
                ln -fs "$HOME/go/bin/$tool_name" /usr/bin/"$tool_name" 2>/dev/null || true
        fi
    done
    
    # Update nuclei templates
    if command -v nuclei &>/dev/null; then
        nuclei -update-templates 2>/dev/null || nuclei --update 2>/dev/null || true
    fi
}

# Install Python-based tools
install_python_tools() {
    echo -e "$OKBLUE[*]$RESET Installing Python-based tools..."
    
    cd "$PLUGINS_DIR" || return
    
    # Sublist3r
    if [[ ! -d "Sublist3r" ]]; then
        echo -e "$OKBLUE[*]$RESET Installing Sublist3r..."
        git clone https://github.com/1N3/Sublist3r.git 2>/dev/null || true
    fi
    
    # Shocker
    if [[ ! -d "shocker" ]]; then
        echo -e "$OKBLUE[*]$RESET Installing Shocker..."
        git clone https://github.com/nccgroup/shocker.git 2>/dev/null || true
    fi
    
    # SSH-Audit
    if [[ ! -d "ssh-audit" ]]; then
        echo -e "$OKBLUE[*]$RESET Installing SSH-Audit..."
        git clone https://github.com/arthepsy/ssh-audit 2>/dev/null || true
    fi
    
    # Jexboss
    if [[ ! -d "jexboss" ]]; then
        echo -e "$OKBLUE[*]$RESET Installing Jexboss..."
        git clone https://github.com/1N3/jexboss.git 2>/dev/null || true
    fi
    
    # WIG
    if [[ ! -d "wig" ]]; then
        echo -e "$OKBLUE[*]$RESET Installing Wig..."
        git clone https://github.com/jekyc/wig.git 2>/dev/null || true
    fi
    
    # CORStest
    if [[ ! -d "CORStest" ]]; then
        echo -e "$OKBLUE[*]$RESET Installing CORStest..."
        git clone https://github.com/RUB-NDS/CORStest.git 2>/dev/null || true
    fi
    
    # Vulscan
    if [[ ! -d "vulscan" ]]; then
        echo -e "$OKBLUE[*]$RESET Installing Vulscan..."
        git clone https://github.com/scipag/vulscan 2>/dev/null || true
    fi
    
    # Metagoofil
    if [[ ! -d "metagoofil" ]]; then
        echo -e "$OKBLUE[*]$RESET Installing Metagoofil..."
        git clone https://github.com/laramies/metagoofil.git 2>/dev/null || true
    fi
    
    # Shodan
    if [[ ! -d "shodan-python" ]]; then
        echo -e "$OKBLUE[*]$RESET Installing Shodan..."
        git clone https://github.com/achillean/shodan-python 2>/dev/null || true
        cd shodan-python && python3 setup.py install 2>/dev/null || true
        cd "$PLUGINS_DIR"
    fi
    
    # CMSMap
    if [[ ! -d "CMSmap" ]]; then
        echo -e "$OKBLUE[*]$RESET Installing CMSMap..."
        git clone https://github.com/Dionach/CMSmap.git 2>/dev/null || true
        cd CMSmap && pip3 install . --break-system-packages 2>/dev/null || pip3 install . 2>/dev/null || true
        python3 setup.py install 2>/dev/null || true
        cd "$PLUGINS_DIR"
    fi
    
    # Smuggler
    if [[ ! -d "smuggler" ]]; then
        echo -e "$OKBLUE[*]$RESET Installing Smuggler..."
        git clone https://github.com/defparam/smuggler.git 2>/dev/null || true
    fi
    
    # Dirsearch
    if [[ ! -d "dirsearch" ]]; then
        echo -e "$OKBLUE[*]$RESET Installing Dirsearch..."
        wget -q https://github.com/maurosoria/dirsearch/archive/refs/tags/v0.4.2.tar.gz -O /tmp/dirsearch.tar.gz
        tar -xzf /tmp/dirsearch.tar.gz -C "$PLUGINS_DIR"
        mv "$PLUGINS_DIR/dirsearch-0.4.2" "$PLUGINS_DIR/dirsearch" 2>/dev/null || true
        cd dirsearch && pip3 install -r requirements.txt --break-system-packages 2>/dev/null || pip3 install -r requirements.txt 2>/dev/null || true
        rm -f /tmp/dirsearch.tar.gz
        cd "$PLUGINS_DIR"
    fi
    
    # SecretFinder
    if [[ ! -d "secretfinder" ]]; then
        echo -e "$OKBLUE[*]$RESET Installing SecretFinder..."
        git clone https://github.com/m4ll0k/SecretFinder.git secretfinder 2>/dev/null || true
        pip3 install -r "$PLUGINS_DIR/secretfinder/requirements.txt" --break-system-packages 2>/dev/null || \
            pip3 install -r "$PLUGINS_DIR/secretfinder/requirements.txt" 2>/dev/null || true
    fi
    
    # LinkFinder
    if [[ ! -d "LinkFinder" ]]; then
        echo -e "$OKBLUE[*]$RESET Installing LinkFinder..."
        git clone https://github.com/1N3/LinkFinder 2>/dev/null || true
        cd LinkFinder && python3 setup.py install 2>/dev/null || true
        cd "$PLUGINS_DIR"
    fi
    
    # GitGraber
    if [[ ! -d "gitGraber" ]]; then
        echo -e "$OKBLUE[*]$RESET Installing GitGrabber..."
        git clone https://github.com/hisxo/gitGraber.git 2>/dev/null || true
        pip3 install -r "$PLUGINS_DIR/gitGraber/requirements.txt" --break-system-packages 2>/dev/null || \
            pip3 install -r "$PLUGINS_DIR/gitGraber/requirements.txt" 2>/dev/null || true
    fi
    
    # Censys-Subdomain-Finder
    if [[ ! -d "censys-subdomain-finder" ]]; then
        echo -e "$OKBLUE[*]$RESET Installing Censys-Subdomain-Finder..."
        git clone https://github.com/christophetd/censys-subdomain-finder.git 2>/dev/null || true
        pip3 install -r "$PLUGINS_DIR/censys-subdomain-finder/requirements.txt" --break-system-packages 2>/dev/null || \
            pip3 install -r "$PLUGINS_DIR/censys-subdomain-finder/requirements.txt" 2>/dev/null || true
    fi
    
    # DNScan
    if [[ ! -d "dnscan" ]]; then
        echo -e "$OKBLUE[*]$RESET Installing DNScan..."
        git clone https://github.com/rbsec/dnscan.git 2>/dev/null || true
        pip3 install -r "$PLUGINS_DIR/dnscan/requirements.txt" --break-system-packages 2>/dev/null || \
            pip3 install -r "$PLUGINS_DIR/dnscan/requirements.txt" 2>/dev/null || true
    fi
    
    # AltDNS
    if [[ ! -d "altdns" ]]; then
        echo -e "$OKBLUE[*]$RESET Installing AltDNS..."
        git clone https://github.com/infosec-au/altdns.git 2>/dev/null || true
        cd altdns
        pip3 install -r requirements.txt --break-system-packages 2>/dev/null || pip3 install -r requirements.txt 2>/dev/null || true
        python3 setup.py install 2>/dev/null || true
        pip3 install py-altdns --break-system-packages 2>/dev/null || pip3 install py-altdns 2>/dev/null || true
        cd "$PLUGINS_DIR"
    fi
    
    # MassDNS
    if [[ ! -d "massdns" ]]; then
        echo -e "$OKBLUE[*]$RESET Installing MassDNS..."
        git clone https://github.com/blechschmidt/massdns.git 2>/dev/null || true
        cd massdns
        make 2>/dev/null && make install 2>/dev/null || true
        cd "$PLUGINS_DIR"
    fi
    
    # DNSGen
    if [[ ! -d "dnsgen" ]]; then
        echo -e "$OKBLUE[*]$RESET Installing DNSGen..."
        git clone https://github.com/ProjectAnte/dnsgen 2>/dev/null || true
        cd dnsgen
        pip3 install -r requirements.txt --break-system-packages 2>/dev/null || pip3 install -r requirements.txt 2>/dev/null || true
        python3 setup.py install 2>/dev/null || true
        cd "$PLUGINS_DIR"
    fi
    
    # BlackWidow
    if [[ ! -d "BlackWidow" ]]; then
        echo -e "$OKBLUE[*]$RESET Installing BlackWidow..."
        git clone https://github.com/1N3/BlackWidow 2>/dev/null || true
        cd BlackWidow && bash install.sh force 2>/dev/null || true
        cd "$PLUGINS_DIR"
    fi
    
    # BruteX
    if [[ ! -d "BruteX" ]]; then
        echo -e "$OKBLUE[*]$RESET Installing BruteX..."
        git clone https://github.com/1N3/BruteX.git 2>/dev/null || true
        cd BruteX && bash install.sh 2>/dev/null || true
        cd "$PLUGINS_DIR"
    fi
    
    # FindSploit
    if [[ ! -d "Findsploit" ]]; then
        echo -e "$OKBLUE[*]$RESET Installing FindSploit..."
        git clone https://github.com/1N3/Findsploit.git 2>/dev/null || true
        cd Findsploit && bash install.sh 2>/dev/null || true
        cd "$PLUGINS_DIR"
    fi
    
    # GooHak
    if [[ ! -d "Goohak" ]]; then
        echo -e "$OKBLUE[*]$RESET Installing GooHak..."
        git clone https://github.com/1N3/Goohak.git 2>/dev/null || true
        chmod +x "$PLUGINS_DIR/Goohak/goohak" 2>/dev/null || true
    fi
}

# Install additional tools
install_additional_tools() {
    echo -e "$OKBLUE[*]$RESET Installing additional tools..."
    
    # GoBuster
    if ! command -v gobuster &>/dev/null; then
        echo -e "$OKBLUE[*]$RESET Installing GoBuster..."
        case "$OS" in
            debian)
                apt install -y gobuster 2>/dev/null || {
                    # Manual install if not in repos
                    wget -q https://github.com/OJ/gobuster/releases/download/v3.0.1/gobuster-linux-amd64.7z -O /tmp/gobuster.7z
                    cd /tmp && 7z e gobuster.7z && chmod +rx gobuster && mv gobuster /usr/bin/gobuster
                }
                ;;
            rhel)
                # Manual install
                wget -q https://github.com/OJ/gobuster/releases/download/v3.0.1/gobuster-linux-amd64.7z -O /tmp/gobuster.7z
                cd /tmp && 7z e gobuster.7z && chmod +rx gobuster && mv gobuster /usr/bin/gobuster
                ;;
            macos)
                brew install gobuster 2>/dev/null || true
                ;;
        esac
    fi
    
    # Arachni (Linux only)
    if [[ "$OS" != "macos" ]] && [[ ! -d "/usr/share/arachni" ]]; then
        echo -e "$OKBLUE[*]$RESET Installing Arachni..."
        wget -q https://github.com/Arachni/arachni/releases/download/v1.5.1/arachni-1.5.1-0.5.12-linux-x86_64.tar.gz -O /tmp/arachni.tar.gz
        cd /tmp && tar -xzf arachni.tar.gz && rm -f arachni.tar.gz
        mkdir -p /usr/share/arachni 2>/dev/null
        cp -Rf arachni-*/* /usr/share/arachni/ 2>/dev/null
        rm -rf arachni-*
        # Create symlinks
        cd /usr/share/arachni/bin/
        for binary in *; do
            ln -fs "$PWD/$binary" /usr/bin/"$binary" 2>/dev/null || true
        done
    fi
    
    # Vulners Nmap Script
    echo -e "$OKBLUE[*]$RESET Installing Vulners Nmap script..."
    local nmap_scripts_dir
    case "$OS" in
        debian|rhel|arch)
            nmap_scripts_dir="/usr/share/nmap/scripts"
            ;;
        macos)
            nmap_scripts_dir="/usr/local/share/nmap/scripts"
            ;;
    esac
    
    if [[ -d "$nmap_scripts_dir" ]]; then
        wget -q https://raw.githubusercontent.com/vulnersCom/nmap-vulners/master/vulners.nse -O "$nmap_scripts_dir/vulners.nse"
        chmod 644 "$nmap_scripts_dir/vulners.nse" 2>/dev/null || true
        nmap --script-updatedb 2>/dev/null || true
    fi
    
    # DNS Resolvers
    echo -e "$OKBLUE[*]$RESET Downloading DNS resolvers list..."
    mkdir -p "$INSTALL_DIR/wordlists" 2>/dev/null
    wget -q https://raw.githubusercontent.com/janmasarik/resolvers/master/resolvers.txt -O "$INSTALL_DIR/wordlists/resolvers.txt" 2>/dev/null || true
}

# Create symlinks
create_symlinks() {
    echo -e "$OKBLUE[*]$RESET Creating symlinks..."
    
    # Main symlinks
    ln -fs "$INSTALL_DIR/sniper" /usr/bin/sniper 2>/dev/null || \
        ln -fs "$INSTALL_DIR/sniper" /usr/local/bin/sniper 2>/dev/null || true
    
    ln -fs "$PLUGINS_DIR/Goohak/goohak" /usr/bin/goohak 2>/dev/null || \
        ln -fs "$PLUGINS_DIR/Goohak/goohak" /usr/local/bin/goohak 2>/dev/null || true
    
    ln -fs "$PLUGINS_DIR/dirsearch/dirsearch.py" /usr/bin/dirsearch 2>/dev/null || \
        ln -fs "$PLUGINS_DIR/dirsearch/dirsearch.py" /usr/local/bin/dirsearch 2>/dev/null || true
    
    # Directory symlinks
    ln -fs /usr/share/sniper /sniper 2>/dev/null || true
    ln -fs /usr/share/sniper /usr/share/sn1per 2>/dev/null || true
    ln -fs /usr/share/sniper/loot/workspaces /workspace 2>/dev/null || true
    
    # User directory symlinks (Linux only)
    if [[ "$OS" != "macos" ]]; then
        ln -fs /usr/share/sniper/loot/workspaces /root/workspace 2>/dev/null || true
        ln -fs /usr/share/sniper /root/sniper 2>/dev/null || true
        ln -fs /root/.sniper.conf /usr/share/sniper/conf/sniper.conf 2>/dev/null || true
        ln -fs /root/.sniper_api_keys.conf /usr/share/sniper/conf/sniper_api_keys.conf 2>/dev/null || true
    fi
}

# Setup desktop shortcuts (Linux only)
setup_desktop_shortcuts() {
    if [[ "$OS" == "macos" ]]; then
        return
    fi
    
    echo -e "$OKBLUE[*]$RESET Setting up desktop shortcuts..."
    
    # Copy desktop files
    cp -f "$INSTALL_DIR/sn1per.desktop" /usr/share/applications/ 2>/dev/null || true
    cp -f "$INSTALL_DIR/sn1per.png" /usr/share/pixmaps/ 2>/dev/null || true
    
    # Kali menu integration
    if [[ -d /usr/share/kali-menu/applications ]]; then
        cp -f "$INSTALL_DIR/sn1per.desktop" /usr/share/kali-menu/applications/ 2>/dev/null || true
    fi
    
    # Plugin desktop files
    if [[ -f "$PLUGINS_DIR/BruteX/brutex.desktop" ]]; then
        cp -f "$PLUGINS_DIR/BruteX/brutex.desktop" /usr/share/applications/ 2>/dev/null || true
        cp -f "$PLUGINS_DIR/BruteX/brutex.desktop" /usr/share/kali-menu/applications/ 2>/dev/null || true
    fi
    
    if [[ -f "$PLUGINS_DIR/BlackWidow/blackwidow.desktop" ]]; then
        cp -f "$PLUGINS_DIR/BlackWidow/blackwidow.desktop" /usr/share/applications/ 2>/dev/null || true
        cp -f "$PLUGINS_DIR/BlackWidow/blackwidow.desktop" /usr/share/kali-menu/applications/ 2>/dev/null || true
    fi
    
    if [[ -f "$PLUGINS_DIR/Findsploit/findsploit.desktop" ]]; then
        cp -f "$PLUGINS_DIR/Findsploit/findsploit.desktop" /usr/share/applications/ 2>/dev/null || true
        cp -f "$PLUGINS_DIR/Findsploit/findsploit.desktop" /usr/share/kali-menu/applications/ 2>/dev/null || true
    fi
    
    # Desktop workspace shortcuts
    ln -fs /usr/share/sniper/loot/workspaces/ /home/kali/Desktop/workspaces 2>/dev/null || true
    ln -fs /usr/share/sniper/loot/workspaces/ /root/Desktop/workspaces 2>/dev/null || true
}

# Setup configuration
setup_configuration() {
    echo -e "$OKBLUE[*]$RESET Setting up configuration..."
    
    if [[ "$OS" != "macos" ]]; then
        # Backup and copy config
        mv /root/.sniper.conf /root/.sniper.conf.bak 2>/dev/null || true
        cp -f "$INSTALL_DIR/sniper.conf" /root/.sniper.conf 2>/dev/null || true
        
        # X11 setup for GUI tools (Linux only)
        if [[ -f /root/.Xauthority ]]; then
            cp -a /root/.Xauthority /root/.Xauthority.bak 2>/dev/null || true
        fi
        
        if [[ "$USER" != "root" ]] && [[ -f /home/$USER/.Xauthority ]]; then
            cp -a /home/$USER/.Xauthority /root/.Xauthority 2>/dev/null || true
            chown root:root /root/.Xauthority 2>/dev/null || true
        fi
    fi
}

# Cleanup
cleanup() {
    echo -e "$OKBLUE[*]$RESET Cleaning up temporary files..."
    rm -rf /tmp/arachni* /tmp/gobuster* /tmp/msfinstall /tmp/openssl.cnf /tmp/dirsearch* 2>/dev/null || true
}

# Main installation flow
main() {
    echo -e "$OKRED[>]$RESET This script will install Sn1per under $INSTALL_DIR."
    
    if [[ "$1" != "force" ]] && [[ "$1" != "-y" ]]; then
        echo -e "$OKRED[>]$RESET Do you want to continue? (y/n) $RESET"
        read -r answer
        if [[ "$answer" != "y" ]] && [[ "$answer" != "Y" ]]; then
            echo -e "$OKRED[>]$RESET Installation cancelled."
            exit 0
        fi
    fi
    
    # Detect OS
    detect_os
    
    # Check root privileges
    check_root
    
    # Create directories
    create_directories
    
    # Install Sn1per files
    install_sniper_files
    
    # Update package repos
    pkg_update
    
    # Install build tools
    install_build_tools
    
    # Install base dependencies
    install_base_dependencies
    
    # Setup language environments
    setup_python
    setup_ruby
    setup_go
    
    # Install tools by category
    install_metasploit
    install_go_tools
    install_python_tools
    install_additional_tools
    
    # Create symlinks
    create_symlinks
    
    # Setup desktop shortcuts (Linux only)
    setup_desktop_shortcuts
    
    # Setup configuration
    setup_configuration
    
    # Cleanup
    cleanup
    
    echo ""
    echo -e "$OKGREEN[✓]$RESET Installation complete!"
    echo -e "$OKGREEN[✓]$RESET To run Sn1per, type: ${OKBLUE}sniper${RESET}"
    echo ""
    echo -e "$OKORANGE[*]$RESET OS Detected: $OS"
    echo -e "$OKORANGE[*]$RESET Install Directory: $INSTALL_DIR"
    echo -e "$OKORANGE[*]$RESET Loot Directory: $LOOT_DIR"
    echo ""
    
    # System-specific notes
    case "$OS" in
        macos)
            echo -e "$OKORANGE[!]$RESET Note: Some tools may require additional configuration on macOS"
            echo -e "$OKORANGE[!]$RESET Run with sudo if you encounter permission issues"
            ;;
        rhel)
            echo -e "$OKORANGE[!]$RESET Note: Some optional tools may not be available in RHEL repos"
            echo -e "$OKORANGE[!]$RESET Consider enabling additional repositories if needed"
            ;;
    esac
}

# Run main installation
main "$@"
