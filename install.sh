#!/usr/bin/env bash
# =============================================================================
# Mavi VPN - Interactive Server Installer
#
# Usage:
#   curl -sSL https://raw.githubusercontent.com/<repo>/install.sh | sudo bash
#   or: sudo bash install.sh
#
# Supports: Ubuntu 20.04+, Debian 11+, CentOS 9+, Fedora 38+, Arch Linux
# =============================================================================

set -euo pipefail

# =============================================================================
# Constants
# =============================================================================

REPO_URL="https://github.com/mavi-vpn/mavi-vpn.git"
INSTALL_DIR="/opt/mavi-vpn"
BACKEND_DIR="${INSTALL_DIR}/backend"

# =============================================================================
# Colors & Formatting
# =============================================================================

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
BOLD='\033[1m'
DIM='\033[2m'
NC='\033[0m' # No Color

# =============================================================================
# Utility Functions
# =============================================================================

print_banner() {
    echo -e "${CYAN}"
    echo "  ╔══════════════════════════════════════════════════════════╗"
    echo "  ║                                                          ║"
    echo "  ║              Mavi VPN - Server Installer                 ║"
    echo "  ║                                                          ║"
    echo "  ╚══════════════════════════════════════════════════════════╝"
    echo -e "${NC}"
}

print_step() {
    local step=$1
    local total=$2
    local title=$3
    echo ""
    echo -e "${BLUE}${BOLD}[$step/$total] $title${NC}"
    echo -e "${DIM}─────────────────────────────────────────────${NC}"
}

print_ok() {
    echo -e "  ${GREEN}✓${NC} $1"
}

print_warn() {
    echo -e "  ${YELLOW}!${NC} $1"
}

print_err() {
    echo -e "  ${RED}✗${NC} $1"
}

print_info() {
    echo -e "  ${DIM}$1${NC}"
}

# Ask a question with a default value.
# Usage: result=$(ask "Question?" "default")
ask() {
    local question=$1
    local default=${2:-}
    local prompt

    if [ -n "$default" ]; then
        prompt="${question} [${default}]: "
    else
        prompt="${question}: "
    fi

    echo -en "  ${BOLD}${prompt}${NC}"
    read -r answer
    echo "${answer:-$default}"
}

# Ask a yes/no question. Returns 0 for yes, 1 for no.
# Usage: if ask_yn "Enable feature?" "y"; then ...
ask_yn() {
    local question=$1
    local default=${2:-n}
    local hint

    if [ "$default" = "y" ]; then
        hint="Y/n"
    else
        hint="y/N"
    fi

    echo -en "  ${BOLD}${question} [${hint}]: ${NC}"
    read -r answer
    answer=${answer:-$default}
    case "$answer" in
        [yY]|[yY][eE][sS]) return 0 ;;
        *) return 1 ;;
    esac
}

# Generate a random token (hex)
generate_token() {
    local length=${1:-32}
    if command -v openssl &>/dev/null; then
        openssl rand -hex "$length"
    else
        head -c "$length" /dev/urandom | xxd -p | tr -d '\n'
    fi
}

# Show a spinner while waiting for a command
spinner() {
    local pid=$1
    local msg=$2
    local spin='⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏'
    local i=0

    while kill -0 "$pid" 2>/dev/null; do
        local c=${spin:i++%${#spin}:1}
        echo -en "\r  ${CYAN}${c}${NC} ${msg}"
        sleep 0.1
    done
    echo -en "\r"
}

# =============================================================================
# System Detection
# =============================================================================

DISTRO=""
PKG_MGR=""

detect_distro() {
    if [ -f /etc/os-release ]; then
        . /etc/os-release
        case "$ID" in
            ubuntu|pop|linuxmint|elementary)
                DISTRO="ubuntu"
                PKG_MGR="apt"
                ;;
            debian)
                DISTRO="debian"
                PKG_MGR="apt"
                ;;
            centos|rocky|alma|rhel|ol)
                DISTRO="centos"
                PKG_MGR="dnf"
                ;;
            fedora)
                DISTRO="fedora"
                PKG_MGR="dnf"
                ;;
            arch|manjaro|endeavouros)
                DISTRO="arch"
                PKG_MGR="pacman"
                ;;
            *)
                DISTRO="unknown"
                ;;
        esac
    else
        DISTRO="unknown"
    fi

    if [ "$DISTRO" = "unknown" ]; then
        print_warn "Could not detect your Linux distribution."
        print_warn "The installer may not work correctly. Proceed with caution."
    else
        print_ok "Detected: ${DISTRO} (${PKG_MGR})"
    fi
}

# =============================================================================
# Prerequisite Checks & Installation
# =============================================================================

install_package() {
    local pkg=$1
    case "$PKG_MGR" in
        apt) apt-get install -y -qq "$pkg" >/dev/null 2>&1 ;;
        dnf) dnf install -y -q "$pkg" >/dev/null 2>&1 ;;
        pacman) pacman -S --noconfirm --needed "$pkg" >/dev/null 2>&1 ;;
        *) print_err "Cannot install $pkg: unknown package manager"; return 1 ;;
    esac
}

install_docker() {
    echo ""
    print_info "Installing Docker..."

    case "$DISTRO" in
        ubuntu|debian)
            # Remove old versions
            apt-get remove -y docker docker-engine docker.io containerd runc >/dev/null 2>&1 || true
            # Install prerequisites
            apt-get update -qq >/dev/null 2>&1
            apt-get install -y -qq ca-certificates curl gnupg >/dev/null 2>&1
            # Add Docker GPG key
            install -m 0755 -d /etc/apt/keyrings
            curl -fsSL "https://download.docker.com/linux/$DISTRO/gpg" | gpg --dearmor -o /etc/apt/keyrings/docker.gpg 2>/dev/null
            chmod a+r /etc/apt/keyrings/docker.gpg
            # Add repository
            echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/$DISTRO $(. /etc/os-release && echo "$VERSION_CODENAME") stable" > /etc/apt/sources.list.d/docker.list
            apt-get update -qq >/dev/null 2>&1
            apt-get install -y -qq docker-ce docker-ce-cli containerd.io docker-compose-plugin >/dev/null 2>&1
            ;;
        fedora)
            dnf -y install dnf-plugins-core >/dev/null 2>&1
            dnf config-manager addrepo --from-repofile="https://download.docker.com/linux/fedora/docker-ce.repo" >/dev/null 2>&1 \
                || dnf config-manager --add-repo "https://download.docker.com/linux/fedora/docker-ce.repo" >/dev/null 2>&1
            dnf install -y docker-ce docker-ce-cli containerd.io docker-compose-plugin >/dev/null 2>&1
            ;;
        centos)
            dnf -y install dnf-plugins-core >/dev/null 2>&1 || yum install -y yum-utils >/dev/null 2>&1
            dnf config-manager addrepo --from-repofile="https://download.docker.com/linux/centos/docker-ce.repo" >/dev/null 2>&1 \
                || dnf config-manager --add-repo "https://download.docker.com/linux/centos/docker-ce.repo" >/dev/null 2>&1 \
                || yum-config-manager --add-repo "https://download.docker.com/linux/centos/docker-ce.repo" >/dev/null 2>&1
            dnf install -y docker-ce docker-ce-cli containerd.io docker-compose-plugin >/dev/null 2>&1 \
                || yum install -y docker-ce docker-ce-cli containerd.io docker-compose-plugin >/dev/null 2>&1
            ;;
        arch)
            pacman -S --noconfirm --needed docker docker-compose >/dev/null 2>&1
            ;;
        *)
            print_err "Cannot install Docker automatically on this system."
            print_err "Please install Docker manually: https://docs.docker.com/engine/install/"
            exit 1
            ;;
    esac

    systemctl enable docker >/dev/null 2>&1
    systemctl start docker >/dev/null 2>&1

    print_ok "Docker installed and started"
}

check_prerequisites() {
    local missing=()

    # Check root
    if [ "$(id -u)" -ne 0 ]; then
        print_err "This script must be run as root (use sudo)."
        exit 1
    fi

    # Docker
    if ! command -v docker &>/dev/null; then
        print_warn "Docker is not installed."
        if ask_yn "Install Docker now?"; then
            install_docker
        else
            print_err "Docker is required. Aborting."
            exit 1
        fi
    else
        print_ok "Docker: $(docker --version 2>/dev/null | head -1)"
    fi

    # Docker Compose v2
    if ! docker compose version &>/dev/null; then
        print_warn "Docker Compose plugin not found."
        if ask_yn "Install Docker Compose plugin now?"; then
            case "$PKG_MGR" in
                apt) apt-get install -y -qq docker-compose-plugin >/dev/null 2>&1 ;;
                dnf) dnf install -y docker-compose-plugin >/dev/null 2>&1 ;;
                pacman) pacman -S --noconfirm --needed docker-compose >/dev/null 2>&1 ;;
            esac
            if docker compose version &>/dev/null; then
                print_ok "Docker Compose installed"
            else
                print_err "Failed to install Docker Compose. Please install manually."
                exit 1
            fi
        else
            print_err "Docker Compose is required. Aborting."
            exit 1
        fi
    else
        print_ok "Docker Compose: $(docker compose version 2>/dev/null | head -1)"
    fi

    # Docker running?
    if ! docker info &>/dev/null; then
        print_warn "Docker daemon is not running. Starting..."
        systemctl start docker 2>/dev/null || service docker start 2>/dev/null
        sleep 2
        if ! docker info &>/dev/null; then
            print_err "Could not start Docker. Please start it manually."
            exit 1
        fi
    fi

    # Git
    if ! command -v git &>/dev/null; then
        print_info "Installing git..."
        install_package git
        print_ok "Git installed"
    else
        print_ok "Git: available"
    fi

    # OpenSSL (for token generation)
    if ! command -v openssl &>/dev/null; then
        print_info "Installing openssl..."
        install_package openssl
    fi

    # Curl
    if ! command -v curl &>/dev/null; then
        print_info "Installing curl..."
        install_package curl
    fi
}

# =============================================================================
# Firewall Configuration
# =============================================================================

configure_firewall() {
    local quic_port=$1
    local tcp_port=$2

    # UFW
    if command -v ufw &>/dev/null && ufw status 2>/dev/null | grep -q "active"; then
        print_info "Configuring UFW firewall..."
        ufw allow "${quic_port}/udp" >/dev/null 2>&1 && print_ok "UFW: opened ${quic_port}/udp (QUIC)"
        ufw allow "${tcp_port}/tcp" >/dev/null 2>&1 && print_ok "UFW: opened ${tcp_port}/tcp (HTTP/2)"
        return
    fi

    # firewalld
    if command -v firewall-cmd &>/dev/null && systemctl is-active --quiet firewalld; then
        print_info "Configuring firewalld..."
        firewall-cmd --permanent --add-port="${quic_port}/udp" >/dev/null 2>&1 && print_ok "firewalld: opened ${quic_port}/udp (QUIC)"
        firewall-cmd --permanent --add-port="${tcp_port}/tcp" >/dev/null 2>&1 && print_ok "firewalld: opened ${tcp_port}/tcp (HTTP/2)"
        firewall-cmd --reload >/dev/null 2>&1
        return
    fi

    print_info "No active firewall detected (ufw/firewalld). Skipping."
}

# =============================================================================
# Existing Installation Check
# =============================================================================

check_existing_install() {
    if [ -d "$INSTALL_DIR" ] || docker ps -a --format '{{.Names}}' 2>/dev/null | grep -q '^mavi-vpn$'; then
        echo ""
        echo -e "${YELLOW}${BOLD}Existing Mavi VPN installation detected!${NC}"
        echo ""
        echo "  1) Reconfigure  - Re-run setup with new settings"
        echo "  2) Update       - Pull latest code and rebuild"
        echo "  3) Uninstall    - Remove everything"
        echo "  4) Abort        - Exit without changes"
        echo ""
        local choice
        choice=$(ask "Choose an option" "1")

        case "$choice" in
            1)
                print_info "Stopping existing containers..."
                cd "$BACKEND_DIR" 2>/dev/null && docker compose down 2>/dev/null || true
                # Continue with normal setup
                ;;
            2)
                print_info "Updating..."
                cd "$INSTALL_DIR"
                git pull 2>/dev/null || print_warn "Git pull failed, continuing with existing code"
                cd "$BACKEND_DIR"
                docker compose build --no-cache 2>&1 | tail -5
                docker compose up -d 2>&1
                echo ""
                print_ok "Update complete!"
                exit 0
                ;;
            3)
                print_info "Stopping and removing..."
                cd "$BACKEND_DIR" 2>/dev/null && docker compose down -v 2>/dev/null || true
                rm -rf "$INSTALL_DIR"
                print_ok "Mavi VPN has been uninstalled."
                exit 0
                ;;
            4)
                echo "Aborted."
                exit 0
                ;;
            *)
                echo "Invalid choice. Aborting."
                exit 1
                ;;
        esac
    fi
}

# =============================================================================
# Let's Encrypt Setup
# =============================================================================

setup_letsencrypt() {
    local domain=$1
    local email=$2

    # Install certbot
    if ! command -v certbot &>/dev/null; then
        print_info "Installing certbot..."
        case "$PKG_MGR" in
            apt)
                apt-get update -qq >/dev/null 2>&1
                apt-get install -y -qq certbot >/dev/null 2>&1
                ;;
            dnf) dnf install -y certbot >/dev/null 2>&1 ;;
            pacman) pacman -S --noconfirm --needed certbot >/dev/null 2>&1 ;;
        esac
    fi

    # Check if port 80 is free (needed for standalone verification)
    if ss -tlnp 2>/dev/null | grep -q ':80 '; then
        print_warn "Port 80 is in use. Certbot needs port 80 for verification."
        print_warn "Please stop the service using port 80 and try again."
        print_info "Common fix: sudo systemctl stop nginx apache2"
        if ! ask_yn "Try anyway?"; then
            print_err "Cannot obtain Let's Encrypt certificate without port 80."
            return 1
        fi
    fi

    # Check if certificate already exists
    if [ -f "/etc/letsencrypt/live/${domain}/fullchain.pem" ]; then
        print_ok "Let's Encrypt certificate already exists for ${domain}"
        return 0
    fi

    print_info "Requesting certificate for ${domain}..."
    if certbot certonly --standalone -d "$domain" --email "$email" --agree-tos --non-interactive 2>&1 | tail -3; then
        print_ok "Certificate obtained for ${domain}"
    else
        print_err "Failed to obtain certificate. Check DNS and firewall settings."
        print_info "Make sure ${domain} points to this server's IP address."
        return 1
    fi
}

# =============================================================================
# Interactive Configuration (9 Steps)
# =============================================================================

# Configuration variables (set by the questionnaire)
CFG_DOMAIN=""
CFG_LETSENCRYPT=false
CFG_ACME_EMAIL=""
CFG_KEYCLOAK=false
CFG_KC_ADMIN_PASS=""
CFG_KC_DB_PASS=""
CFG_KC_AUTH_DOMAIN=""
CFG_AUTH_TOKEN=""
CFG_NETWORK="10.8.0.0/24"
CFG_DNS="1.1.1.1"
CFG_QUIC_PORT="4433"
CFG_TCP_PORT="443"
CFG_CENSORSHIP_RESISTANT=false
CFG_MSS_CLAMPING=true

run_questionnaire() {

    # --- Step 1: Domain ---
    print_step 1 9 "Server Domain"
    echo -e "  ${DIM}Enter the domain name or IP address that clients will connect to.${NC}"
    echo -e "  ${DIM}Example: vpn.example.com or 203.0.113.10${NC}"
    echo ""
    CFG_DOMAIN=$(ask "Server domain/IP" "")

    if [ -z "$CFG_DOMAIN" ]; then
        print_err "Domain cannot be empty."
        exit 1
    fi

    # Strip protocol prefix if accidentally included
    CFG_DOMAIN="${CFG_DOMAIN#https://}"
    CFG_DOMAIN="${CFG_DOMAIN#http://}"
    CFG_DOMAIN="${CFG_DOMAIN%%/*}" # Strip trailing path

    print_ok "Domain: ${CFG_DOMAIN}"

    # --- Step 2: Let's Encrypt ---
    print_step 2 9 "TLS Certificates"
    echo -e "  ${DIM}Let's Encrypt provides free, trusted TLS certificates.${NC}"
    echo -e "  ${DIM}Requires: a valid domain name (not an IP) and port 80 open.${NC}"
    echo -e "  ${DIM}If you skip this, the server will generate a self-signed certificate.${NC}"
    echo ""

    if ask_yn "Use Let's Encrypt for trusted certificates?" "y"; then
        CFG_LETSENCRYPT=true
        CFG_ACME_EMAIL=$(ask "Email for Let's Encrypt notifications" "")
        if [ -z "$CFG_ACME_EMAIL" ]; then
            print_warn "Email is required for Let's Encrypt."
            CFG_ACME_EMAIL=$(ask "Email" "")
        fi
        print_ok "Let's Encrypt enabled (${CFG_ACME_EMAIL})"
    else
        CFG_LETSENCRYPT=false
        print_ok "Using self-signed certificates"
    fi

    # --- Step 3: Keycloak ---
    print_step 3 9 "Authentication Method"
    echo -e "  ${DIM}Keycloak provides Single Sign-On (SSO) with user management.${NC}"
    echo -e "  ${DIM}Users get their own accounts with passwords.${NC}"
    echo -e "  ${DIM}Without Keycloak, all users share a single pre-shared key.${NC}"
    echo ""

    if ask_yn "Enable Keycloak (SSO) authentication?" "n"; then
        CFG_KEYCLOAK=true

        CFG_KC_AUTH_DOMAIN=$(ask "Keycloak domain" "auth.${CFG_DOMAIN}")
        echo ""
        echo -e "  ${DIM}Set passwords for Keycloak. Leave empty to auto-generate.${NC}"
        echo ""

        CFG_KC_ADMIN_PASS=$(ask "Keycloak admin password" "")
        if [ -z "$CFG_KC_ADMIN_PASS" ]; then
            CFG_KC_ADMIN_PASS=$(generate_token 16)
            print_info "Generated admin password: ${CFG_KC_ADMIN_PASS}"
        fi

        CFG_KC_DB_PASS=$(ask "Keycloak database password" "")
        if [ -z "$CFG_KC_DB_PASS" ]; then
            CFG_KC_DB_PASS=$(generate_token 16)
            print_info "Generated DB password (internal use only)"
        fi

        print_ok "Keycloak enabled at ${CFG_KC_AUTH_DOMAIN}"
    else
        CFG_KEYCLOAK=false
        print_ok "Using pre-shared key authentication"
    fi

    # --- Step 4: Auth Token ---
    print_step 4 9 "VPN Authentication Token"
    if [ "$CFG_KEYCLOAK" = true ]; then
        echo -e "  ${DIM}Since Keycloak is enabled, users will log in with their accounts.${NC}"
        echo -e "  ${DIM}A fallback token is still generated for emergency access.${NC}"
        echo ""
    else
        echo -e "  ${DIM}This token is the password that all clients need to connect.${NC}"
        echo -e "  ${DIM}Leave empty to auto-generate a secure random token.${NC}"
        echo ""
    fi

    CFG_AUTH_TOKEN=$(ask "Auth token" "")
    if [ -z "$CFG_AUTH_TOKEN" ]; then
        CFG_AUTH_TOKEN=$(generate_token 32)
        print_ok "Generated token: ${CFG_AUTH_TOKEN}"
    else
        print_ok "Token set (custom)"
    fi

    # --- Step 5: Network ---
    print_step 5 9 "VPN Network"
    echo -e "  ${DIM}The private IP range used inside the VPN tunnel.${NC}"
    echo -e "  ${DIM}Default is fine for most setups. Change only if it conflicts${NC}"
    echo -e "  ${DIM}with your existing local network.${NC}"
    echo ""

    CFG_NETWORK=$(ask "VPN network (CIDR)" "10.8.0.0/24")
    print_ok "Network: ${CFG_NETWORK}"

    # --- Step 6: DNS ---
    print_step 6 9 "DNS Server"
    echo -e "  ${DIM}The DNS server that connected clients will use.${NC}"
    echo ""
    echo "  1) Cloudflare   (1.1.1.1)     - Fast, privacy-focused"
    echo "  2) Google       (8.8.8.8)     - Reliable"
    echo "  3) Quad9        (9.9.9.9)     - Security-focused"
    echo "  4) Custom"
    echo ""

    local dns_choice
    dns_choice=$(ask "Choose DNS" "1")
    case "$dns_choice" in
        1) CFG_DNS="1.1.1.1" ;;
        2) CFG_DNS="8.8.8.8" ;;
        3) CFG_DNS="9.9.9.9" ;;
        4) CFG_DNS=$(ask "Custom DNS IP" "1.1.1.1") ;;
        *) CFG_DNS="1.1.1.1" ;;
    esac
    print_ok "DNS: ${CFG_DNS}"

    # --- Step 7: Ports ---
    print_step 7 9 "Ports"
    echo -e "  ${DIM}QUIC port (UDP): The primary VPN transport, very fast.${NC}"
    echo -e "  ${DIM}TCP port:  HTTP/2 fallback for strict firewalls.${NC}"
    echo ""

    CFG_QUIC_PORT=$(ask "QUIC port (UDP)" "4433")
    CFG_TCP_PORT=$(ask "TCP fallback port" "443")

    # Check for port conflicts
    if ss -tlnp 2>/dev/null | grep -q ":${CFG_TCP_PORT} "; then
        print_warn "Port ${CFG_TCP_PORT}/tcp appears to be in use!"
        print_info "Check with: ss -tlnp | grep :${CFG_TCP_PORT}"
        if ! ask_yn "Continue anyway?"; then
            CFG_TCP_PORT=$(ask "Alternative TCP port" "8443")
        fi
    fi

    print_ok "QUIC: ${CFG_QUIC_PORT}/udp, TCP: ${CFG_TCP_PORT}/tcp"

    # --- Step 8: Censorship Resistance ---
    print_step 8 9 "Censorship Resistance"
    echo -e "  ${DIM}When enabled, the VPN server disguises itself as a normal${NC}"
    echo -e "  ${DIM}HTTP/3 web server. Helps bypass deep packet inspection.${NC}"
    echo -e "  ${DIM}Only enable if you're in a censored network.${NC}"
    echo ""

    if ask_yn "Enable censorship resistance?" "n"; then
        CFG_CENSORSHIP_RESISTANT=true
    else
        CFG_CENSORSHIP_RESISTANT=false
    fi
    print_ok "Censorship resistance: ${CFG_CENSORSHIP_RESISTANT}"

    # --- Step 9: MSS Clamping ---
    print_step 9 9 "TCP MSS Clamping"
    echo -e "  ${DIM}Prevents fragmentation issues in the VPN tunnel.${NC}"
    echo -e "  ${DIM}Recommended to keep enabled.${NC}"
    echo ""

    if ask_yn "Enable TCP MSS Clamping?" "y"; then
        CFG_MSS_CLAMPING=true
    else
        CFG_MSS_CLAMPING=false
    fi
    print_ok "MSS Clamping: ${CFG_MSS_CLAMPING}"
}

# =============================================================================
# Configuration Summary
# =============================================================================

print_summary() {
    echo ""
    echo -e "${CYAN}${BOLD}"
    echo "  ┌────────────────────────────────────────────────────────┐"
    echo "  │                 Configuration Summary                  │"
    echo "  ├────────────────────────────────────────────────────────┤"
    printf "  │  %-20s %-35s│\n" "Domain:" "$CFG_DOMAIN"
    if [ "$CFG_LETSENCRYPT" = true ]; then
    printf "  │  %-20s %-35s│\n" "TLS:" "Let's Encrypt ($CFG_ACME_EMAIL)"
    else
    printf "  │  %-20s %-35s│\n" "TLS:" "Self-signed (auto-generated)"
    fi
    if [ "$CFG_KEYCLOAK" = true ]; then
    printf "  │  %-20s %-35s│\n" "Auth:" "Keycloak SSO ($CFG_KC_AUTH_DOMAIN)"
    else
    printf "  │  %-20s %-35s│\n" "Auth:" "Pre-shared token"
    fi
    printf "  │  %-20s %-35s│\n" "Network:" "$CFG_NETWORK"
    printf "  │  %-20s %-35s│\n" "DNS:" "$CFG_DNS"
    printf "  │  %-20s %-35s│\n" "Ports:" "QUIC ${CFG_QUIC_PORT}/udp, TCP ${CFG_TCP_PORT}/tcp"
    printf "  │  %-20s %-35s│\n" "Censorship Resist.:" "$CFG_CENSORSHIP_RESISTANT"
    printf "  │  %-20s %-35s│\n" "MSS Clamping:" "$CFG_MSS_CLAMPING"
    echo "  └────────────────────────────────────────────────────────┘"
    echo -e "${NC}"
}

# =============================================================================
# Installation Steps
# =============================================================================

setup_directory() {
    if [ -d "$INSTALL_DIR/.git" ]; then
        print_info "Repository already exists, pulling latest changes..."
        cd "$INSTALL_DIR"
        git pull 2>/dev/null || print_warn "Git pull failed, using existing code"
    else
        print_info "Cloning Mavi VPN repository..."
        rm -rf "$INSTALL_DIR" 2>/dev/null || true
        git clone "$REPO_URL" "$INSTALL_DIR" 2>&1 | tail -2
    fi
    print_ok "Source code ready at ${INSTALL_DIR}"
}

generate_env_file() {
    local env_file="${BACKEND_DIR}/.env"

    # Determine certificate paths
    local cert_path key_path
    if [ "$CFG_LETSENCRYPT" = true ]; then
        cert_path="/etc/letsencrypt/live/${CFG_DOMAIN}/fullchain.pem"
        key_path="/etc/letsencrypt/live/${CFG_DOMAIN}/privkey.pem"
    else
        cert_path="data/cert.pem"
        key_path="data/key.pem"
    fi

    cat > "$env_file" << ENVEOF
# Mavi VPN Server Configuration
# Generated by install.sh on $(date -u +"%Y-%m-%d %H:%M:%S UTC")

# Logging
RUST_LOG=info

# VPN Bind Addresses
VPN_BIND_ADDR=0.0.0.0:${CFG_QUIC_PORT}
VPN_BIND_ADDR_TCP=0.0.0.0:${CFG_TCP_PORT}

# Authentication
VPN_AUTH_TOKEN=${CFG_AUTH_TOKEN}

# Network
VPN_NETWORK=${CFG_NETWORK}
VPN_DNS=${CFG_DNS}

# TLS Certificates
VPN_CERT=${cert_path}
VPN_KEY=${key_path}

# Features
VPN_CENSORSHIP_RESISTANT=${CFG_CENSORSHIP_RESISTANT}
VPN_MSS_CLAMPING=${CFG_MSS_CLAMPING}

# Domain (used by Traefik/Keycloak)
DOMAIN_NAME=${CFG_DOMAIN}
ACME_EMAIL=${CFG_ACME_EMAIL:-none}
ENVEOF

    # Add Keycloak config if enabled
    if [ "$CFG_KEYCLOAK" = true ]; then
        cat >> "$env_file" << KCEOF

# Keycloak Configuration
COMPOSE_FILE=docker-compose.yml:keycloak/docker-compose.yml
COMPOSE_PROFILES=traefik,keycloak
KEYCLOAK_ENABLED=true
KEYCLOAK_URL=https://${CFG_KC_AUTH_DOMAIN}
KEYCLOAK_REALM=mavi-vpn
KEYCLOAK_CLIENT_ID=mavi-client
KEYCLOAK_DB_PASSWORD=${CFG_KC_DB_PASS}
KEYCLOAK_ADMIN_USER=admin
KEYCLOAK_ADMIN_PASS=${CFG_KC_ADMIN_PASS}

# Traefik Ports (for Keycloak reverse proxy)
TRAEFIK_HTTP_PORT=80
TRAEFIK_HTTPS_PORT=443
TRAEFIK_ACME_RESOLVER=myresolver
KCEOF
    fi

    chmod 600 "$env_file"
    print_ok "Configuration written to ${env_file}"
}

build_and_start() {
    cd "$BACKEND_DIR"

    print_info "Building Docker images (this may take a few minutes on first run)..."
    if docker compose build 2>&1 | tail -5; then
        print_ok "Docker images built successfully"
    else
        print_err "Build failed. Check the output above."
        exit 1
    fi

    print_info "Starting containers..."
    if docker compose up -d 2>&1; then
        print_ok "Containers started"
    else
        print_err "Failed to start containers."
        exit 1
    fi

    # Wait for VPN server to be healthy
    print_info "Waiting for VPN server to initialize..."
    local attempts=0
    local max_attempts=60

    while [ $attempts -lt $max_attempts ]; do
        local status
        status=$(docker inspect --format='{{.State.Health.Status}}' mavi-vpn 2>/dev/null || echo "starting")
        if [ "$status" = "healthy" ]; then
            print_ok "VPN server is healthy and running!"
            return 0
        fi

        # Check if container crashed
        local running
        running=$(docker inspect --format='{{.State.Running}}' mavi-vpn 2>/dev/null || echo "false")
        if [ "$running" = "false" ]; then
            print_err "Container crashed. Showing logs:"
            docker logs mavi-vpn --tail 20 2>&1
            exit 1
        fi

        attempts=$((attempts + 1))
        sleep 2
    done

    print_warn "Server didn't become healthy within 120 seconds."
    print_info "It may still be starting. Check logs with:"
    print_info "  cd ${BACKEND_DIR} && docker compose logs -f"
}

# =============================================================================
# Config Code Generation
# =============================================================================

get_cert_pin() {
    local pin=""

    # Try reading from data/cert_pin.txt (self-signed certs)
    if [ -f "${BACKEND_DIR}/data/cert_pin.txt" ]; then
        pin=$(cat "${BACKEND_DIR}/data/cert_pin.txt" 2>/dev/null | tr -d '[:space:]')
    fi

    # Try reading from Let's Encrypt cert_pin.txt
    if [ -z "$pin" ] && [ -f "/etc/letsencrypt/live/${CFG_DOMAIN}/cert_pin.txt" ]; then
        pin=$(cat "/etc/letsencrypt/live/${CFG_DOMAIN}/cert_pin.txt" 2>/dev/null | tr -d '[:space:]')
    fi

    # Try reading from docker logs
    if [ -z "$pin" ]; then
        pin=$(docker logs mavi-vpn 2>&1 | grep -oP 'Certificate PIN: \K[a-f0-9]+' | tail -1)
    fi

    echo "$pin"
}

generate_config_code() {
    local cert_pin=$1

    # Build JSON
    local kc_bool="false"
    local kc_fields=""

    if [ "$CFG_KEYCLOAK" = true ]; then
        kc_bool="true"
        kc_fields=$(printf ',"kc_url":"https://%s","kc_realm":"mavi-vpn","kc_client_id":"mavi-client"' "$CFG_KC_AUTH_DOMAIN")
    fi

    local json
    json=$(printf '{"v":1,"endpoint":"%s:%s","cert_pin":"%s","cr":%s,"tcp":false,"kc":%s%s}' \
        "$CFG_DOMAIN" "$CFG_QUIC_PORT" "$cert_pin" "$CFG_CENSORSHIP_RESISTANT" "$kc_bool" "$kc_fields")

    # Base64url encode (URL-safe, no padding)
    local encoded
    encoded=$(echo -n "$json" | base64 -w0 | tr '+/' '-_' | tr -d '=')

    echo "mavi://${encoded}"
}

# =============================================================================
# Post-Install Output
# =============================================================================

print_success_banner() {
    local cert_pin=$1
    local config_code=$2

    echo ""
    echo -e "${GREEN}${BOLD}"
    echo "  ╔══════════════════════════════════════════════════════════╗"
    echo "  ║                                                          ║"
    echo "  ║          Mavi VPN Server - Installation Complete!        ║"
    echo "  ║                                                          ║"
    echo "  ╚══════════════════════════════════════════════════════════╝"
    echo -e "${NC}"

    # Certificate PIN
    echo -e "${BOLD}  Certificate PIN:${NC}"
    echo -e "  ${CYAN}${cert_pin}${NC}"
    echo ""

    # Auth Token (only show if not using Keycloak exclusively)
    if [ "$CFG_KEYCLOAK" = false ]; then
        echo -e "${BOLD}  Auth Token:${NC}"
        echo -e "  ${CYAN}${CFG_AUTH_TOKEN}${NC}"
        echo ""
    fi

    # Config Code
    echo -e "${BOLD}  Config Code (share this with your clients):${NC}"
    echo -e "  ${DIM}Copy this entire line and paste it into the Mavi VPN app:${NC}"
    echo ""
    echo -e "  ${GREEN}${config_code}${NC}"
    echo ""

    # Client instructions
    echo -e "${BOLD}  How to connect clients:${NC}"
    echo -e "  ${DIM}1. Install Mavi VPN on your device${NC}"
    echo -e "  ${DIM}2. Paste the config code above into the app (or use: mavi-vpn import <code>)${NC}"
    if [ "$CFG_KEYCLOAK" = true ]; then
        echo -e "  ${DIM}3. Log in with your Keycloak account${NC}"
    else
        echo -e "  ${DIM}3. Enter the auth token shown above${NC}"
    fi
    echo -e "  ${DIM}4. Click Connect!${NC}"
    echo ""

    if [ "$CFG_KEYCLOAK" = true ]; then
        echo -e "${BOLD}  Keycloak Admin Console:${NC}"
        echo -e "  ${CYAN}https://${CFG_KC_AUTH_DOMAIN}${NC}"
        echo -e "  ${DIM}Username: admin${NC}"
        echo -e "  ${DIM}Password: ${CFG_KC_ADMIN_PASS}${NC}"
        echo ""
        echo -e "  ${BOLD}Keycloak Setup (required):${NC}"
        echo -e "  ${DIM}1. Open the Keycloak admin console URL above${NC}"
        echo -e "  ${DIM}2. Create a realm named: mavi-vpn${NC}"
        echo -e "  ${DIM}3. Create a client named: mavi-client${NC}"
        echo -e "  ${DIM}   - Client authentication: OFF (public client)${NC}"
        echo -e "  ${DIM}   - Valid redirect URIs:${NC}"
        echo -e "  ${DIM}     http://127.0.0.1:18923/callback${NC}"
        echo -e "  ${DIM}     mavivpn://oauth${NC}"
        echo -e "  ${DIM}4. Create user accounts under 'Users'${NC}"
        echo ""
    fi

    # Management
    echo -e "${BOLD}  Management Commands:${NC}"
    echo -e "  ${DIM}cd ${BACKEND_DIR}${NC}"
    echo -e "  ${DIM}docker compose logs -f          # View live logs${NC}"
    echo -e "  ${DIM}docker compose restart           # Restart server${NC}"
    echo -e "  ${DIM}docker compose down              # Stop server${NC}"
    echo -e "  ${DIM}docker compose up -d             # Start server${NC}"
    echo -e "  ${DIM}sudo bash ${INSTALL_DIR}/install.sh   # Reconfigure${NC}"
    echo ""
}

# =============================================================================
# Main
# =============================================================================

main() {
    print_banner

    # Must be root
    if [ "$(id -u)" -ne 0 ]; then
        print_err "This script must be run as root."
        echo -e "  ${DIM}Run: sudo bash install.sh${NC}"
        exit 1
    fi

    # Detect distro
    detect_distro

    # Check for existing installation
    check_existing_install

    # Check prerequisites
    print_step 0 9 "Prerequisites"
    check_prerequisites

    # Run the 9-step questionnaire
    run_questionnaire

    # Show summary and confirm
    print_summary
    echo ""
    if ! ask_yn "Proceed with installation?" "y"; then
        echo "Installation cancelled."
        exit 0
    fi

    # Execute installation
    echo ""
    echo -e "${BOLD}Starting installation...${NC}"
    echo ""

    # 1. Setup directory
    print_info "Setting up installation directory..."
    setup_directory

    # 2. Generate .env
    print_info "Generating configuration..."
    generate_env_file

    # 3. Let's Encrypt (if enabled)
    if [ "$CFG_LETSENCRYPT" = true ]; then
        print_info "Setting up Let's Encrypt..."
        if ! setup_letsencrypt "$CFG_DOMAIN" "$CFG_ACME_EMAIL"; then
            print_warn "Let's Encrypt setup failed. Falling back to self-signed certificates."
            # Update .env to use self-signed certs
            sed -i "s|VPN_CERT=.*|VPN_CERT=data/cert.pem|" "${BACKEND_DIR}/.env"
            sed -i "s|VPN_KEY=.*|VPN_KEY=data/key.pem|" "${BACKEND_DIR}/.env"
        fi
    fi

    # 4. Configure firewall
    print_info "Configuring firewall..."
    configure_firewall "$CFG_QUIC_PORT" "$CFG_TCP_PORT"
    # Also open port 80 for Let's Encrypt renewals
    if [ "$CFG_LETSENCRYPT" = true ]; then
        if command -v ufw &>/dev/null && ufw status 2>/dev/null | grep -q "active"; then
            ufw allow 80/tcp >/dev/null 2>&1
        fi
        if command -v firewall-cmd &>/dev/null && systemctl is-active --quiet firewalld; then
            firewall-cmd --permanent --add-service=http >/dev/null 2>&1
            firewall-cmd --reload >/dev/null 2>&1
        fi
    fi

    # 5. Build and start
    build_and_start

    # 6. Get certificate PIN
    print_info "Retrieving certificate PIN..."
    sleep 3 # Give the server a moment to write cert_pin.txt
    local cert_pin
    cert_pin=$(get_cert_pin)

    if [ -z "$cert_pin" ]; then
        print_warn "Could not retrieve certificate PIN automatically."
        print_info "Check: docker logs mavi-vpn | grep 'Certificate PIN'"
        cert_pin="<check docker logs>"
    fi

    # 7. Generate config code
    local config_code=""
    if [ "$cert_pin" != "<check docker logs>" ]; then
        config_code=$(generate_config_code "$cert_pin")
    else
        config_code="<generate after obtaining cert pin>"
    fi

    # 8. Show success
    print_success_banner "$cert_pin" "$config_code"
}

main "$@"
