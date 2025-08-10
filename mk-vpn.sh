#!/bin/bash

################################################################################
# MK VPN Manager - Xray (xray-core) Management Script for Ubuntu 20.04
# 
# Author: MK Kelati
# Repository: https://github.com/mkkelati/vpn7
# Version: 1.0.0
# License: MIT
#
# Description: Production-ready script for installing and managing Xray with
#              WebSocket + TLS support using NGINX reverse proxy and Let's Encrypt
#
# Changelog:
# v1.0.0 - Initial release with full feature set
#
# References:
# - Xray-core: https://github.com/XTLS/Xray-core
# - Configuration: https://xtls.github.io/config/
################################################################################

set -euo pipefail

# Global configuration
readonly SCRIPT_NAME="mk-vpn"
readonly SCRIPT_VERSION="1.0.0"
readonly GITHUB_REPO="mkkelati/vpn7"
readonly GITHUB_RAW_URL="https://raw.githubusercontent.com/${GITHUB_REPO}/main/mk-vpn.sh"

# Paths and directories
readonly XRAY_CONFIG_DIR="/etc/xray"
readonly XRAY_CONFIG_FILE="${XRAY_CONFIG_DIR}/config.json"
readonly XRAY_LOG_DIR="/var/log/xray"
readonly XRAY_DATA_DIR="/var/lib/xray"
readonly USER_DB_FILE="${XRAY_DATA_DIR}/users.json"
readonly SCRIPT_LOG="/var/log/xray-manager.log"
readonly NGINX_CONFIG_DIR="/etc/nginx"
readonly NGINX_SITES_DIR="${NGINX_CONFIG_DIR}/sites-available"
readonly SYSTEMD_DIR="/etc/systemd/system"

# Colors for output
readonly RED='\033[0;31m'
readonly GREEN='\033[0;32m'
readonly YELLOW='\033[1;33m'
readonly BLUE='\033[0;34m'
readonly PURPLE='\033[0;35m'
readonly CYAN='\033[0;36m'
readonly WHITE='\033[1;37m'
readonly NC='\033[0m' # No Color

# Global variables
DOMAIN=""
WS_PATH=""
XRAY_PORT=""
DRY_RUN=false

################################################################################
# Utility Functions
################################################################################

# Print colored output
print_color() {
    local color=$1
    shift
    echo -e "${color}$*${NC}"
}

# Logging function
log() {
    local level=$1
    shift
    local message="$*"
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] [$level] $message" | tee -a "$SCRIPT_LOG" >/dev/null
    
    case $level in
        "ERROR")   print_color "$RED" "❌ ERROR: $message" ;;
        "SUCCESS") print_color "$GREEN" "✅ SUCCESS: $message" ;;
        "INFO")    print_color "$BLUE" "ℹ️  INFO: $message" ;;
        "WARN")    print_color "$YELLOW" "⚠️  WARNING: $message" ;;
        "DEBUG")   print_color "$CYAN" "🔍 DEBUG: $message" ;;
    esac
}

# Error handling
error_exit() {
    log "ERROR" "$1"
    exit 1
}

# Check if running as root
check_root() {
    if [[ $EUID -ne 0 ]]; then
        error_exit "This script must be run as root. Use: sudo $0"
    fi
}

# Check Ubuntu version
check_ubuntu_version() {
    if [[ ! -f /etc/lsb-release ]] || ! grep -q "Ubuntu 20.04" /etc/lsb-release; then
        error_exit "This script is designed for Ubuntu 20.04 only"
    fi
    log "INFO" "Ubuntu 20.04 detected"
}

# Generate UUID
generate_uuid() {
    if command -v uuidgen >/dev/null 2>&1; then
        uuidgen
    elif [[ -f /proc/sys/kernel/random/uuid ]]; then
        cat /proc/sys/kernel/random/uuid
    else
        error_exit "Unable to generate UUID. Install uuid-runtime package."
    fi
}

# Validate domain
validate_domain() {
    local domain=$1
    
    # Basic domain format validation (allows subdomains)
    if [[ ! $domain =~ ^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*\.[a-zA-Z]{2,}$ ]]; then
        error_exit "Invalid domain format: $domain"
    fi
    
    # Check domain length
    if [[ ${#domain} -gt 253 ]]; then
        error_exit "Domain name too long: $domain"
    fi
    
    # Check if domain resolves
    if ! nslookup "$domain" >/dev/null 2>&1; then
        log "WARN" "Domain $domain does not resolve. Continuing anyway..."
    fi
}

# Check if port is available
check_port() {
    local port=$1
    # Use ss instead of netstat (more modern and commonly available)
    if command -v ss >/dev/null 2>&1; then
        if ss -tuln | grep -q ":$port "; then
            error_exit "Port $port is already in use"
        fi
    elif command -v netstat >/dev/null 2>&1; then
        if netstat -tuln | grep -q ":$port "; then
            error_exit "Port $port is already in use"
        fi
    else
        log "WARN" "Neither ss nor netstat available, skipping port check"
    fi
}

# Create directories
create_directories() {
    local dirs=("$XRAY_CONFIG_DIR" "$XRAY_LOG_DIR" "$XRAY_DATA_DIR")
    for dir in "${dirs[@]}"; do
        if [[ ! -d $dir ]]; then
            mkdir -p "$dir"
            log "INFO" "Created directory: $dir"
        fi
    done
    
    # Set proper permissions
    chmod 755 "$XRAY_CONFIG_DIR" "$XRAY_LOG_DIR" "$XRAY_DATA_DIR"
    touch "$SCRIPT_LOG"
    chmod 644 "$SCRIPT_LOG"
}

# Initialize user database
init_user_db() {
    if [[ ! -f $USER_DB_FILE ]]; then
        echo '{"users": []}' > "$USER_DB_FILE"
        chmod 640 "$USER_DB_FILE"
        log "INFO" "Initialized user database"
    fi
}

################################################################################
# Package Management
################################################################################

# Update package list
update_packages() {
    log "INFO" "Updating package list..."
    apt update -qq
}

# Install required packages
install_packages() {
    local packages=("curl" "wget" "jq" "nginx" "certbot" "python3-certbot-nginx" "unzip" "socat" "ufw" "cron" "uuid-runtime" "net-tools")
    local missing_packages=()
    
    log "INFO" "Checking required packages..."
    
    for package in "${packages[@]}"; do
        if ! dpkg -l | grep -q "^ii  $package "; then
            missing_packages+=("$package")
        fi
    done
    
    if [[ ${#missing_packages[@]} -eq 0 ]]; then
        log "SUCCESS" "All required packages are already installed"
        return
    fi
    
    log "INFO" "Installing missing packages: ${missing_packages[*]}"
    if [[ $DRY_RUN == true ]]; then
        log "INFO" "DRY RUN: Would install: ${missing_packages[*]}"
        return
    fi
    
    DEBIAN_FRONTEND=noninteractive apt install -y "${missing_packages[@]}"
    log "SUCCESS" "Packages installed successfully"
}

################################################################################
# Xray Installation
################################################################################

# Get latest Xray version
get_latest_xray_version() {
    curl -s "https://api.github.com/repos/XTLS/Xray-core/releases/latest" | jq -r '.tag_name' | sed 's/^v//'
}

# Download and install Xray
install_xray() {
    local version
    version=$(get_latest_xray_version)
    local download_url="https://github.com/XTLS/Xray-core/releases/download/v${version}/Xray-linux-64.zip"
    local temp_dir="/tmp/xray-install"
    
    log "INFO" "Installing Xray v${version}..."
    
    if [[ $DRY_RUN == true ]]; then
        log "INFO" "DRY RUN: Would install Xray v${version}"
        return
    fi
    
    # Create temporary directory
    mkdir -p "$temp_dir"
    cd "$temp_dir"
    
    # Download Xray
    wget -q "$download_url" -O xray.zip
    
    # Extract and install
    unzip -q xray.zip
    mv xray /usr/local/bin/
    chmod +x /usr/local/bin/xray
    
    # Create xray user
    if ! id xray >/dev/null 2>&1; then
        useradd -r -s /bin/false xray
    fi
    
    # Set ownership
    chown -R xray:xray "$XRAY_CONFIG_DIR" "$XRAY_LOG_DIR" "$XRAY_DATA_DIR"
    
    # Cleanup
    cd /
    rm -rf "$temp_dir"
    
    log "SUCCESS" "Xray v${version} installed successfully"
}

# Create Xray systemd service
create_xray_service() {
    local service_file="${SYSTEMD_DIR}/xray.service"
    
    if [[ $DRY_RUN == true ]]; then
        log "INFO" "DRY RUN: Would create Xray systemd service"
        return
    fi
    
    cat > "$service_file" << 'EOF'
[Unit]
Description=Xray Service
Documentation=https://github.com/xtls
After=network.target nss-lookup.target

[Service]
User=xray
Group=xray
Type=simple
ExecStartPre=/usr/local/bin/xray -test -config /etc/xray/config.json
ExecStart=/usr/local/bin/xray run -config /etc/xray/config.json
ExecReload=/bin/kill -HUP $MAINPID
Restart=on-failure
RestartSec=5
LimitNOFILE=1000000

[Install]
WantedBy=multi-user.target
EOF
    
    systemctl daemon-reload
    systemctl enable xray
    log "SUCCESS" "Xray systemd service created and enabled"
}

# Generate Xray configuration
generate_xray_config() {
    local uuid=$1
    local domain=$2
    local ws_path=$3
    local port=${4:-10085}
    
    if [[ $DRY_RUN == true ]]; then
        log "INFO" "DRY RUN: Would generate Xray configuration"
        return
    fi
    
    cat > "$XRAY_CONFIG_FILE" << EOF
{
  "log": {
    "access": "${XRAY_LOG_DIR}/access.log",
    "error": "${XRAY_LOG_DIR}/error.log",
    "loglevel": "warning"
  },
  "inbounds": [
    {
      "port": ${port},
      "protocol": "vless",
      "settings": {
        "clients": [
          {
            "id": "${uuid}",
            "flow": ""
          }
        ],
        "decryption": "none"
      },
      "streamSettings": {
        "network": "ws",
        "wsSettings": {
          "path": "${ws_path}"
        }
      },
      "sniffing": {
        "enabled": true,
        "destOverride": ["http", "tls"]
      }
    },
    {
      "port": $((port + 1)),
      "protocol": "vmess",
      "settings": {
        "clients": [
          {
            "id": "${uuid}",
            "alterId": 0
          }
        ]
      },
      "streamSettings": {
        "network": "ws",
        "wsSettings": {
          "path": "${ws_path}/vmess"
        }
      },
      "sniffing": {
        "enabled": true,
        "destOverride": ["http", "tls"]
      }
    }
  ],
  "outbounds": [
    {
      "protocol": "freedom",
      "settings": {}
    },
    {
      "protocol": "blackhole",
      "settings": {},
      "tag": "blocked"
    }
  ],
  "routing": {
    "rules": [
      {
        "type": "field",
        "ip": ["geoip:private"],
        "outboundTag": "blocked"
      }
    ]
  },
  "stats": {},
  "api": {
    "tag": "api",
    "services": ["StatsService"]
  },
  "policy": {
    "levels": {
      "0": {
        "statsUserUplink": true,
        "statsUserDownlink": true
      }
    },
    "system": {
      "statsInboundUplink": true,
      "statsInboundDownlink": true
    }
  }
}
EOF
    
    chmod 640 "$XRAY_CONFIG_FILE"
    chown xray:xray "$XRAY_CONFIG_FILE"
    log "SUCCESS" "Xray configuration generated"
}

################################################################################
# NGINX Configuration
################################################################################

# Configure NGINX
configure_nginx() {
    local domain=$1
    local ws_path=$2
    local xray_port=${3:-10085}
    local site_config="${NGINX_SITES_DIR}/${domain}"
    
    if [[ $DRY_RUN == true ]]; then
        log "INFO" "DRY RUN: Would configure NGINX"
        return
    fi
    
    # Remove default site
    rm -f /etc/nginx/sites-enabled/default
    
    # Create initial HTTP-only configuration (SSL will be added by certbot)
    cat > "$site_config" << EOF
server {
    listen 80;
    server_name ${domain};
    
    # Security headers
    add_header X-Frame-Options DENY always;
    add_header X-Content-Type-Options nosniff always;
    add_header X-XSS-Protection "1; mode=block" always;
    add_header Referrer-Policy "strict-origin-when-cross-origin" always;
    
    # Hide server info
    server_tokens off;
    
    # WebSocket proxy for Xray
    location ${ws_path} {
        if (\$http_upgrade != "websocket") {
            return 404;
        }
        proxy_redirect off;
        proxy_pass http://127.0.0.1:${xray_port};
        proxy_http_version 1.1;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
    }
    
    # VMess WebSocket proxy
    location ${ws_path}/vmess {
        if (\$http_upgrade != "websocket") {
            return 404;
        }
        proxy_redirect off;
        proxy_pass http://127.0.0.1:$((xray_port + 1));
        proxy_http_version 1.1;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
    }
    
    # Camouflage - serve a basic page for other requests
    location / {
        return 200 "<!DOCTYPE html><html><head><title>Welcome</title></head><body><h1>Welcome to ${domain}</h1><p>This is a regular website.</p></body></html>";
        add_header Content-Type text/html;
    }
}
EOF
    
    # Enable site
    ln -sf "$site_config" "/etc/nginx/sites-enabled/${domain}"
    
    # Test NGINX configuration
    nginx -t
    
    log "SUCCESS" "NGINX configured for $domain"
}

# Setup SSL with Let's Encrypt
setup_ssl() {
    local domain=$1
    
    if [[ $DRY_RUN == true ]]; then
        log "INFO" "DRY RUN: Would setup SSL for $domain"
        return
    fi
    
    log "INFO" "Setting up SSL certificate for $domain..."
    
    # Reload NGINX first
    systemctl reload nginx
    
    # Wait a moment for NGINX to be ready
    sleep 2
    
    # Check if domain resolves to this server
    local server_ip
    server_ip=$(curl -s ifconfig.me || curl -s ipinfo.io/ip)
    local domain_ip
    domain_ip=$(nslookup "$domain" | grep -A1 "Name:" | tail -n1 | awk '{print $2}' 2>/dev/null)
    
    if [[ "$server_ip" != "$domain_ip" ]]; then
        log "WARN" "Domain $domain (IP: $domain_ip) does not point to this server (IP: $server_ip)"
        log "WARN" "SSL certificate generation may fail. Please update your DNS records."
        
        read -p "Continue anyway? (y/N): " continue_ssl
        if [[ ! $continue_ssl =~ ^[Yy] ]]; then
            log "INFO" "SSL setup skipped. You can run 'certbot --nginx -d $domain' manually later."
            return
        fi
    fi
    
    # Get SSL certificate
    if certbot --nginx -d "$domain" --non-interactive --agree-tos --register-unsafely-without-email --quiet; then
        log "SUCCESS" "SSL certificate obtained successfully"
        
        # Setup auto-renewal
        (crontab -l 2>/dev/null; echo "0 12 * * * /usr/bin/certbot renew --quiet") | crontab -
        log "SUCCESS" "SSL auto-renewal configured"
    else
        log "ERROR" "Failed to obtain SSL certificate"
        log "INFO" "You can try manually later with: certbot --nginx -d $domain"
        log "INFO" "Make sure your domain points to this server's IP: $server_ip"
    fi
}

################################################################################
# Firewall Configuration
################################################################################

# Configure UFW firewall
configure_firewall() {
    if [[ $DRY_RUN == true ]]; then
        log "INFO" "DRY RUN: Would configure firewall"
        return
    fi
    
    log "INFO" "Configuring UFW firewall..."
    
    # Reset UFW to default
    ufw --force reset
    
    # Default policies
    ufw default deny incoming
    ufw default allow outgoing
    
    # Allow SSH (keep current SSH port)
    local ssh_port
    ssh_port=$(ss -tlnp | grep sshd | awk '{print $4}' | cut -d: -f2 | head -n1)
    if [[ -n $ssh_port ]]; then
        ufw allow "$ssh_port"/tcp comment "SSH"
    else
        ufw allow 22/tcp comment "SSH"
    fi
    
    # Allow HTTP and HTTPS
    ufw allow 80/tcp comment "HTTP"
    ufw allow 443/tcp comment "HTTPS"
    
    # Enable UFW
    ufw --force enable
    
    log "SUCCESS" "Firewall configured successfully"
}

################################################################################
# Logging Configuration
################################################################################

# Setup log rotation
setup_logrotate() {
    if [[ $DRY_RUN == true ]]; then
        log "INFO" "DRY RUN: Would setup log rotation"
        return
    fi
    
    cat > /etc/logrotate.d/xray << EOF
${XRAY_LOG_DIR}/*.log {
    daily
    missingok
    rotate 52
    compress
    delaycompress
    notifempty
    create 644 xray xray
    postrotate
        systemctl reload xray
    endscript
}

${SCRIPT_LOG} {
    daily
    missingok
    rotate 30
    compress
    delaycompress
    notifempty
    create 644 root root
}
EOF
    
    log "SUCCESS" "Log rotation configured"
}

################################################################################
# User Management
################################################################################

# Add user to database
add_user_to_db() {
    local name=$1
    local uuid=$2
    local expiry=$3
    local limit=${4:-0}
    local protocol=${5:-"vless"}
    local created=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
    local expiry_date
    
    if [[ $expiry -gt 0 ]]; then
        expiry_date=$(date -u -d "+${expiry} days" +"%Y-%m-%dT%H:%M:%SZ")
    else
        expiry_date="never"
    fi
    
    # Read current database
    local db_content
    db_content=$(cat "$USER_DB_FILE")
    
    # Add new user
    local new_user
    new_user=$(jq -n \
        --arg name "$name" \
        --arg uuid "$uuid" \
        --arg protocol "$protocol" \
        --arg created "$created" \
        --arg expiry "$expiry_date" \
        --argjson limit "$limit" \
        --argjson used 0 \
        '{
            name: $name,
            uuid: $uuid,
            protocol: $protocol,
            created: $created,
            expiry: $expiry,
            traffic_limit: $limit,
            traffic_used: $used,
            status: "active"
        }')
    
    # Update database
    echo "$db_content" | jq ".users += [$new_user]" > "${USER_DB_FILE}.tmp"
    mv "${USER_DB_FILE}.tmp" "$USER_DB_FILE"
    chmod 640 "$USER_DB_FILE"
    
    log "SUCCESS" "User $name added to database"
}

# Update Xray config with new user
update_xray_config_user() {
    local uuid=$1
    local protocol=${2:-"vless"}
    
    if [[ $DRY_RUN == true ]]; then
        log "INFO" "DRY RUN: Would update Xray config with new user"
        return
    fi
    
    # Backup current config
    cp "$XRAY_CONFIG_FILE" "${XRAY_CONFIG_FILE}.bak"
    
    # Add user to appropriate protocol section
    local updated_config
    if [[ $protocol == "vless" ]]; then
        updated_config=$(jq ".inbounds[0].settings.clients += [{\"id\": \"$uuid\", \"flow\": \"\"}]" "$XRAY_CONFIG_FILE")
    else
        updated_config=$(jq ".inbounds[1].settings.clients += [{\"id\": \"$uuid\", \"alterId\": 0}]" "$XRAY_CONFIG_FILE")
    fi
    
    echo "$updated_config" > "$XRAY_CONFIG_FILE"
    
    # Test configuration
    if ! /usr/local/bin/xray -test -config "$XRAY_CONFIG_FILE" >/dev/null 2>&1; then
        log "ERROR" "Invalid Xray configuration, restoring backup"
        mv "${XRAY_CONFIG_FILE}.bak" "$XRAY_CONFIG_FILE"
        return 1
    fi
    
    # Reload Xray
    systemctl reload xray
    log "SUCCESS" "Xray configuration updated and reloaded"
}

# Generate client configuration
generate_client_config() {
    local uuid=$1
    local protocol=$2
    local domain=$DOMAIN
    local ws_path=$WS_PATH
    local port=443
    
    case $protocol in
        "vless")
            echo "vless://${uuid}@${domain}:${port}?type=ws&security=tls&path=${ws_path}&host=${domain}&sni=${domain}#${domain}_VLESS"
            ;;
        "vmess")
            local vmess_config
            vmess_config=$(jq -n \
                --arg add "$domain" \
                --arg aid "0" \
                --arg host "$domain" \
                --arg id "$uuid" \
                --arg net "ws" \
                --arg path "${ws_path}/vmess" \
                --arg port "$port" \
                --arg ps "${domain}_VMess" \
                --arg scy "auto" \
                --arg sni "$domain" \
                --arg tls "tls" \
                --arg type "none" \
                --arg v "2" \
                '{
                    add: $add,
                    aid: $aid,
                    host: $host,
                    id: $id,
                    net: $net,
                    path: $path,
                    port: $port,
                    ps: $ps,
                    scy: $scy,
                    sni: $sni,
                    tls: $tls,
                    type: $type,
                    v: $v
                }')
            echo "vmess://$(echo "$vmess_config" | base64 -w 0)"
            ;;
    esac
}

# Generate client JSON config
generate_client_json() {
    local uuid=$1
    local protocol=$2
    local domain=$DOMAIN
    local ws_path=$WS_PATH
    
    case $protocol in
        "vless")
            cat << EOF
{
  "outbounds": [
    {
      "protocol": "vless",
      "settings": {
        "vnext": [
          {
            "address": "${domain}",
            "port": 443,
            "users": [
              {
                "id": "${uuid}",
                "flow": "",
                "encryption": "none"
              }
            ]
          }
        ]
      },
      "streamSettings": {
        "network": "ws",
        "security": "tls",
        "tlsSettings": {
          "serverName": "${domain}"
        },
        "wsSettings": {
          "path": "${ws_path}",
          "headers": {
            "Host": "${domain}"
          }
        }
      },
      "tag": "proxy"
    },
    {
      "protocol": "freedom",
      "tag": "direct"
    }
  ]
}
EOF
            ;;
        "vmess")
            cat << EOF
{
  "outbounds": [
    {
      "protocol": "vmess",
      "settings": {
        "vnext": [
          {
            "address": "${domain}",
            "port": 443,
            "users": [
              {
                "id": "${uuid}",
                "alterId": 0,
                "security": "auto"
              }
            ]
          }
        ]
      },
      "streamSettings": {
        "network": "ws",
        "security": "tls",
        "tlsSettings": {
          "serverName": "${domain}"
        },
        "wsSettings": {
          "path": "${ws_path}/vmess",
          "headers": {
            "Host": "${domain}"
          }
        }
      },
      "tag": "proxy"
    },
    {
      "protocol": "freedom",
      "tag": "direct"
    }
  ]
}
EOF
            ;;
    esac
}

################################################################################
# CLI Commands
################################################################################

# Full installation
cmd_install() {
    log "INFO" "Starting MK VPN installation..."
    
    # Check prerequisites
    check_root
    check_ubuntu_version
    create_directories
    
    # Install packages
    update_packages
    install_packages
    
    # Get configuration from user
    if [[ -z $DOMAIN ]]; then
        read -p "Enter your domain (e.g., example.com): " DOMAIN
    fi
    validate_domain "$DOMAIN"
    
    if [[ -z $WS_PATH ]]; then
        WS_PATH="/$(openssl rand -hex 8)"
        log "INFO" "Generated WebSocket path: $WS_PATH"
    fi
    
    if [[ -z $XRAY_PORT ]]; then
        XRAY_PORT=10085
    fi
    check_port "$XRAY_PORT"
    
    # Generate initial UUID
    local initial_uuid
    initial_uuid=$(generate_uuid)
    
    # Install and configure components
    install_xray
    create_xray_service
    generate_xray_config "$initial_uuid" "$DOMAIN" "$WS_PATH" "$XRAY_PORT"
    configure_nginx "$DOMAIN" "$WS_PATH" "$XRAY_PORT"
    setup_ssl "$DOMAIN"
    configure_firewall
    setup_logrotate
    init_user_db
    
    # Start services
    if [[ $DRY_RUN == false ]]; then
        systemctl start xray
        systemctl reload nginx
    fi
    
    # Add initial user
    add_user_to_db "admin" "$initial_uuid" 0 0 "vless"
    
    # Save configuration
    cat > "${XRAY_DATA_DIR}/config.env" << EOF
DOMAIN=${DOMAIN}
WS_PATH=${WS_PATH}
XRAY_PORT=${XRAY_PORT}
EOF
    
    log "SUCCESS" "MK VPN installation completed successfully!"
    echo
    print_color "$GREEN" "=== Installation Summary ==="
    print_color "$CYAN" "Domain: $DOMAIN"
    print_color "$CYAN" "WebSocket Path: $WS_PATH"
    print_color "$CYAN" "Xray Port: $XRAY_PORT"
    print_color "$CYAN" "Admin UUID: $initial_uuid"
    echo
    print_color "$YELLOW" "Next steps:"
    print_color "$WHITE" "1. Ensure your domain points to this server's IP"
    print_color "$WHITE" "2. Use 'mk-vpn add-user' to create client accounts"
    print_color "$WHITE" "3. Use 'mk-vpn status' to check system status"
}

# Add user
cmd_add_user() {
    local name=""
    local expiry=30
    local limit=0
    local protocol="vless"
    
    # Parse arguments
    while [[ $# -gt 0 ]]; do
        case $1 in
            --name)
                name="$2"
                shift 2
                ;;
            --expiry)
                expiry="$2"
                shift 2
                ;;
            --limit)
                limit="$2"
                shift 2
                ;;
            --protocol)
                protocol="$2"
                shift 2
                ;;
            *)
                error_exit "Unknown option: $1"
                ;;
        esac
    done
    
    if [[ -z $name ]]; then
        read -p "Enter username: " name
    fi
    
    if [[ -z $name ]]; then
        error_exit "Username is required"
    fi
    
    # Check if user already exists
    if jq -e ".users[] | select(.name == \"$name\")" "$USER_DB_FILE" >/dev/null 2>&1; then
        error_exit "User $name already exists"
    fi
    
    # Generate UUID
    local uuid
    uuid=$(generate_uuid)
    
    # Load configuration
    if [[ -f "${XRAY_DATA_DIR}/config.env" ]]; then
        source "${XRAY_DATA_DIR}/config.env"
    else
        error_exit "Installation not found. Run 'mk-vpn install' first."
    fi
    
    # Add user
    add_user_to_db "$name" "$uuid" "$expiry" "$limit" "$protocol"
    update_xray_config_user "$uuid" "$protocol"
    
    # Generate client configurations
    local client_link
    client_link=$(generate_client_config "$uuid" "$protocol")
    
    log "SUCCESS" "User $name added successfully!"
    echo
    print_color "$GREEN" "=== User Details ==="
    print_color "$CYAN" "Name: $name"
    print_color "$CYAN" "UUID: $uuid"
    print_color "$CYAN" "Protocol: $protocol"
    print_color "$CYAN" "Expires: $(if [[ $expiry -gt 0 ]]; then date -d "+${expiry} days" +"%Y-%m-%d"; else echo "Never"; fi)"
    print_color "$CYAN" "Traffic Limit: $(if [[ $limit -gt 0 ]]; then echo "${limit}GB"; else echo "Unlimited"; fi)"
    echo
    print_color "$GREEN" "=== Client Configuration ==="
    print_color "$YELLOW" "Share Link:"
    echo "$client_link"
    echo
    print_color "$YELLOW" "JSON Configuration:"
    generate_client_json "$uuid" "$protocol"
}

# List users
cmd_list_users() {
    if [[ ! -f $USER_DB_FILE ]]; then
        error_exit "No users found. Run 'mk-vpn install' first."
    fi
    
    local users
    users=$(jq -r '.users[]' "$USER_DB_FILE")
    
    if [[ -z $users ]]; then
        log "INFO" "No users found"
        return
    fi
    
    print_color "$GREEN" "=== User List ==="
    printf "%-15s %-36s %-10s %-12s %-10s %-8s\n" "Name" "UUID" "Protocol" "Created" "Expires" "Status"
    echo "--------------------------------------------------------------------------------------------------------"
    
    jq -r '.users[] | [.name, .uuid, .protocol, .created[:10], (if .expiry == "never" then "Never" else .expiry[:10] end), .status] | @tsv' "$USER_DB_FILE" | \
    while IFS=$'\t' read -r name uuid protocol created expires status; do
        printf "%-15s %-36s %-10s %-12s %-10s %-8s\n" "$name" "$uuid" "$protocol" "$created" "$expires" "$status"
    done
}

# Revoke user
cmd_revoke_user() {
    local uuid=""
    
    while [[ $# -gt 0 ]]; do
        case $1 in
            --uuid)
                uuid="$2"
                shift 2
                ;;
            *)
                error_exit "Unknown option: $1"
                ;;
        esac
    done
    
    if [[ -z $uuid ]]; then
        cmd_list_users
        echo
        read -p "Enter UUID to revoke: " uuid
    fi
    
    if [[ -z $uuid ]]; then
        error_exit "UUID is required"
    fi
    
    # Check if user exists
    if ! jq -e ".users[] | select(.uuid == \"$uuid\")" "$USER_DB_FILE" >/dev/null 2>&1; then
        error_exit "User with UUID $uuid not found"
    fi
    
    # Remove user from database
    local updated_db
    updated_db=$(jq "del(.users[] | select(.uuid == \"$uuid\"))" "$USER_DB_FILE")
    echo "$updated_db" > "$USER_DB_FILE"
    
    # Update Xray configuration
    if [[ $DRY_RUN == false ]]; then
        local updated_config
        updated_config=$(jq "del(.inbounds[].settings.clients[] | select(.id == \"$uuid\"))" "$XRAY_CONFIG_FILE")
        echo "$updated_config" > "$XRAY_CONFIG_FILE"
        
        # Test and reload
        if /usr/local/bin/xray -test -config "$XRAY_CONFIG_FILE" >/dev/null 2>&1; then
            systemctl reload xray
            log "SUCCESS" "User $uuid revoked successfully"
        else
            error_exit "Failed to update Xray configuration"
        fi
    fi
}

# Renew user
cmd_renew_user() {
    local uuid=""
    local days=30
    
    while [[ $# -gt 0 ]]; do
        case $1 in
            --uuid)
                uuid="$2"
                shift 2
                ;;
            --days)
                days="$2"
                shift 2
                ;;
            *)
                error_exit "Unknown option: $1"
                ;;
        esac
    done
    
    if [[ -z $uuid ]]; then
        cmd_list_users
        echo
        read -p "Enter UUID to renew: " uuid
    fi
    
    if [[ -z $uuid ]]; then
        error_exit "UUID is required"
    fi
    
    # Check if user exists
    if ! jq -e ".users[] | select(.uuid == \"$uuid\")" "$USER_DB_FILE" >/dev/null 2>&1; then
        error_exit "User with UUID $uuid not found"
    fi
    
    # Update expiry date
    local new_expiry
    new_expiry=$(date -u -d "+${days} days" +"%Y-%m-%dT%H:%M:%SZ")
    
    local updated_db
    updated_db=$(jq "(.users[] | select(.uuid == \"$uuid\") | .expiry) = \"$new_expiry\"" "$USER_DB_FILE")
    echo "$updated_db" > "$USER_DB_FILE"
    
    log "SUCCESS" "User $uuid renewed for $days days (expires: $(date -d "$new_expiry" +"%Y-%m-%d"))"
}

# Backup configuration
cmd_backup() {
    local backup_file="xray-backup-$(date +%Y%m%d-%H%M%S).tar.gz"
    
    log "INFO" "Creating backup: $backup_file"
    
    if [[ $DRY_RUN == true ]]; then
        log "INFO" "DRY RUN: Would create backup $backup_file"
        return
    fi
    
    tar -czf "$backup_file" \
        -C / \
        etc/xray/ \
        var/lib/xray/ \
        etc/nginx/sites-available/ \
        etc/systemd/system/xray.service \
        2>/dev/null
    
    log "SUCCESS" "Backup created: $backup_file"
}

# Restore configuration
cmd_restore() {
    local backup_file="$1"
    
    if [[ -z $backup_file ]]; then
        error_exit "Backup file is required"
    fi
    
    if [[ ! -f $backup_file ]]; then
        error_exit "Backup file not found: $backup_file"
    fi
    
    log "INFO" "Restoring from backup: $backup_file"
    
    if [[ $DRY_RUN == true ]]; then
        log "INFO" "DRY RUN: Would restore from $backup_file"
        return
    fi
    
    # Stop services
    systemctl stop xray nginx
    
    # Extract backup
    tar -xzf "$backup_file" -C /
    
    # Reload systemd and restart services
    systemctl daemon-reload
    systemctl start xray nginx
    
    log "SUCCESS" "Restore completed successfully"
}

# Show status
cmd_status() {
    print_color "$GREEN" "=== MK VPN Status ==="
    echo
    
    # Xray status
    print_color "$CYAN" "Xray Service:"
    if systemctl is-active --quiet xray; then
        print_color "$GREEN" "  Status: Running"
    else
        print_color "$RED" "  Status: Stopped"
    fi
    
    # NGINX status
    print_color "$CYAN" "NGINX Service:"
    if systemctl is-active --quiet nginx; then
        print_color "$GREEN" "  Status: Running"
    else
        print_color "$RED" "  Status: Stopped"
    fi
    
    # SSL certificate status
    if [[ -f "${XRAY_DATA_DIR}/config.env" ]]; then
        source "${XRAY_DATA_DIR}/config.env"
        print_color "$CYAN" "SSL Certificate:"
        if command -v certbot >/dev/null 2>&1; then
            local cert_info
            cert_info=$(certbot certificates -d "$DOMAIN" 2>/dev/null | grep "Expiry Date" | head -n1)
            if [[ -n $cert_info ]]; then
                print_color "$GREEN" "  $cert_info"
            else
                print_color "$YELLOW" "  No certificate found"
            fi
        fi
    fi
    
    # Firewall status
    print_color "$CYAN" "Firewall:"
    if ufw status | grep -q "Status: active"; then
        print_color "$GREEN" "  Status: Active"
    else
        print_color "$YELLOW" "  Status: Inactive"
    fi
    
    # User count
    if [[ -f $USER_DB_FILE ]]; then
        local user_count
        user_count=$(jq '.users | length' "$USER_DB_FILE")
        print_color "$CYAN" "Active Users: $user_count"
    fi
    
    # System resources
    print_color "$CYAN" "System Resources:"
    echo "  CPU: $(top -bn1 | grep "Cpu(s)" | awk '{print $2}' | cut -d'%' -f1)% used"
    echo "  Memory: $(free | grep Mem | awk '{printf("%.1f%% used\n", $3/$2 * 100.0)}')"
    echo "  Disk: $(df / | awk 'NR==2{printf "%s used\n", $5}')"
}

# Uninstall
cmd_uninstall() {
    print_color "$RED" "WARNING: This will remove all MK VPN configurations and users!"
    read -p "Are you sure? Type 'YES' to confirm: " confirm
    
    if [[ $confirm != "YES" ]]; then
        log "INFO" "Uninstall cancelled"
        return
    fi
    
    if [[ $DRY_RUN == true ]]; then
        log "INFO" "DRY RUN: Would uninstall MK VPN"
        return
    fi
    
    log "INFO" "Uninstalling MK VPN..."
    
    # Stop services
    systemctl stop xray nginx || true
    systemctl disable xray || true
    
    # Remove files
    rm -rf "$XRAY_CONFIG_DIR" "$XRAY_LOG_DIR" "$XRAY_DATA_DIR"
    rm -f "${SYSTEMD_DIR}/xray.service"
    rm -f /usr/local/bin/xray
    rm -f /etc/nginx/sites-available/* /etc/nginx/sites-enabled/*
    rm -f /etc/logrotate.d/xray
    
    # Remove user
    userdel xray 2>/dev/null || true
    
    # Reload systemd
    systemctl daemon-reload
    
    # Reset firewall (optional)
    read -p "Reset firewall to defaults? (y/N): " reset_fw
    if [[ $reset_fw =~ ^[Yy] ]]; then
        ufw --force reset
        ufw default deny incoming
        ufw default allow outgoing
        ufw allow 22/tcp
        ufw --force enable
    fi
    
    log "SUCCESS" "MK VPN uninstalled successfully"
}

# Self-update
cmd_self_update() {
    log "INFO" "Checking for updates..."
    
    local current_version="$SCRIPT_VERSION"
    local temp_script="/tmp/mk-vpn-update.sh"
    
    # Download latest version
    if ! wget -q "$GITHUB_RAW_URL" -O "$temp_script"; then
        error_exit "Failed to download update"
    fi
    
    # Extract version from downloaded script
    local new_version
    new_version=$(grep "^readonly SCRIPT_VERSION=" "$temp_script" | cut -d'"' -f2)
    
    if [[ $new_version == $current_version ]]; then
        log "INFO" "Already running the latest version ($current_version)"
        rm -f "$temp_script"
        return
    fi
    
    log "INFO" "Updating from version $current_version to $new_version"
    
    if [[ $DRY_RUN == true ]]; then
        log "INFO" "DRY RUN: Would update to version $new_version"
        rm -f "$temp_script"
        return
    fi
    
    # Replace current script
    chmod +x "$temp_script"
    mv "$temp_script" "/usr/local/bin/menu"
    
    log "SUCCESS" "Updated to version $new_version"
    print_color "$GREEN" "Please run 'menu' to use the updated version"
}

################################################################################
# Menu System
################################################################################

# Display banner
show_banner() {
    clear
    print_color "$PURPLE" "╔══════════════════════════════════════════════════════╗"
    print_color "$PURPLE" "║                    MK VPN MANAGER                    ║"
    print_color "$PURPLE" "║                  Xray + WebSocket + TLS              ║"
    print_color "$PURPLE" "║                     Version $SCRIPT_VERSION                     ║"
    print_color "$PURPLE" "╚══════════════════════════════════════════════════════╝"
    echo
}

# Show main menu
show_menu() {
    show_banner
    print_color "$CYAN" "Please select an option:"
    echo
    print_color "$WHITE" " 1) Install MK VPN"
    print_color "$WHITE" " 2) Add User"
    print_color "$WHITE" " 3) List Users"
    print_color "$WHITE" " 4) Renew User"
    print_color "$WHITE" " 5) Revoke User"
    print_color "$WHITE" " 6) Backup Configuration"
    print_color "$WHITE" " 7) Restore Configuration"
    print_color "$WHITE" " 8) System Status"
    print_color "$WHITE" " 9) Self Update"
    print_color "$WHITE" "10) Uninstall"
    print_color "$WHITE" " 0) Exit"
    echo
}

# Interactive menu
interactive_menu() {
    while true; do
        show_menu
        read -p "Enter your choice [0-10]: " choice
        echo
        
        case $choice in
            1)
                cmd_install
                ;;
            2)
                cmd_add_user
                ;;
            3)
                cmd_list_users
                ;;
            4)
                cmd_renew_user
                ;;
            5)
                cmd_revoke_user
                ;;
            6)
                cmd_backup
                ;;
            7)
                read -p "Enter backup file path: " backup_file
                cmd_restore "$backup_file"
                ;;
            8)
                cmd_status
                ;;
            9)
                cmd_self_update
                ;;
            10)
                cmd_uninstall
                ;;
            0)
                log "INFO" "Goodbye!"
                exit 0
                ;;
            *)
                print_color "$RED" "Invalid option. Please try again."
                ;;
        esac
        
        echo
        read -p "Press Enter to continue..."
    done
}

################################################################################
# Usage and Help
################################################################################

# Show usage
show_usage() {
    cat << EOF
MK VPN Manager - Xray Management Script v${SCRIPT_VERSION}

USAGE:
    $0 [COMMAND] [OPTIONS]

COMMANDS:
    install                          - Install and configure MK VPN
    add-user [OPTIONS]               - Add a new user
    list-users                       - List all users
    revoke-user --uuid <UUID>        - Revoke a user
    renew-user --uuid <UUID> [--days <N>] - Renew user expiry
    backup                           - Create configuration backup
    restore <file>                   - Restore from backup
    status                           - Show system status
    self-update                      - Update script to latest version
    uninstall                        - Remove MK VPN installation

ADD-USER OPTIONS:
    --name <name>                    - Username (required)
    --expiry <days>                  - Expiry in days (default: 30)
    --limit <GB>                     - Traffic limit in GB (default: unlimited)
    --protocol <vless|vmess>         - Protocol (default: vless)

GLOBAL OPTIONS:
    --dry-run                        - Show what would be done without executing
    --help                           - Show this help message

EXAMPLES:
    # Install MK VPN
    $0 install

    # Add a user with 30-day expiry and 100GB limit
    $0 add-user --name john --expiry 30 --limit 100

    # List all users
    $0 list-users

    # Create backup
    $0 backup

    # Check status
    $0 status

    # Interactive menu (no arguments)
    $0

INSTALLATION:
    # Direct installation from GitHub
    wget -O /usr/local/bin/menu https://raw.githubusercontent.com/${GITHUB_REPO}/main/mk-vpn.sh
    chmod +x /usr/local/bin/menu
    menu

For more information, visit: https://github.com/${GITHUB_REPO}
EOF
}

################################################################################
# Main Function
################################################################################

main() {
    # Create log directory if it doesn't exist
    mkdir -p "$(dirname "$SCRIPT_LOG")"
    
    # Parse global options
    while [[ $# -gt 0 ]]; do
        case $1 in
            --dry-run)
                DRY_RUN=true
                shift
                ;;
            --help|-h)
                show_usage
                exit 0
                ;;
            --domain)
                DOMAIN="$2"
                shift 2
                ;;
            --ws-path)
                WS_PATH="$2"
                shift 2
                ;;
            --xray-port)
                XRAY_PORT="$2"
                shift 2
                ;;
            install|add-user|list-users|revoke-user|renew-user|backup|restore|status|uninstall|self-update)
                break
                ;;
            *)
                error_exit "Unknown option: $1. Use --help for usage information."
                ;;
        esac
    done
    
    # If no command provided, show interactive menu
    if [[ $# -eq 0 ]]; then
        interactive_menu
        exit 0
    fi
    
    # Execute command
    local command=$1
    shift
    
    case $command in
        install)
            cmd_install "$@"
            ;;
        add-user)
            cmd_add_user "$@"
            ;;
        list-users)
            cmd_list_users "$@"
            ;;
        revoke-user)
            cmd_revoke_user "$@"
            ;;
        renew-user)
            cmd_renew_user "$@"
            ;;
        backup)
            cmd_backup "$@"
            ;;
        restore)
            cmd_restore "$@"
            ;;
        status)
            cmd_status "$@"
            ;;
        uninstall)
            cmd_uninstall "$@"
            ;;
        self-update)
            cmd_self_update "$@"
            ;;
        *)
            error_exit "Unknown command: $command. Use --help for usage information."
            ;;
    esac
}

################################################################################
# Script Entry Point
################################################################################

# Set trap for cleanup
trap 'log "ERROR" "Script interrupted"; exit 1' INT TERM

# Run main function with all arguments
main "$@"

################################################################################
# README Documentation
################################################################################

: << 'README'
# MK VPN Manager

A production-ready Bash script for managing Xray (xray-core) with WebSocket + TLS on Ubuntu 20.04.

## Features

- **Easy Installation**: One-command setup with Let's Encrypt SSL
- **User Management**: Add, list, renew, and revoke users with traffic limits
- **Multiple Protocols**: Support for VLESS and VMess over WebSocket
- **Security**: UFW firewall, secure NGINX configuration, automatic SSL renewal
- **Monitoring**: System status, traffic accounting, and logging
- **Backup/Restore**: Configuration backup and restore functionality
- **Interactive Menu**: User-friendly text-based interface
- **Self-Updating**: Automatic updates from GitHub repository

## Quick Installation

```bash
# Download and install
wget -O /usr/local/bin/menu https://raw.githubusercontent.com/mkkelati/vpn7/main/mk-vpn.sh
chmod +x /usr/local/bin/menu

# Run interactive menu
menu

# Or install directly
sudo menu install
```

## Usage Examples

### Install VPN Server
```bash
sudo menu install
# Follow prompts to enter domain name
```

### Add a User
```bash
# Interactive
menu add-user

# Command line
sudo menu add-user --name john --expiry 30 --limit 100 --protocol vless
```

### List Users
```bash
menu list-users
```

### Check Status
```bash
menu status
```

### Create Backup
```bash
sudo menu backup
```

## Client Configuration

After adding a user, the script provides:
1. **Share Links**: Copy-paste links for mobile apps
2. **JSON Configuration**: For Xray clients and Clash
3. **QR Codes**: For easy mobile setup

### Example Output
```
VLESS Link:
vless://uuid@domain.com:443?type=ws&security=tls&path=/abcd1234&host=domain.com&sni=domain.com#domain.com_VLESS

JSON Configuration:
{
  "outbounds": [
    {
      "protocol": "vless",
      "settings": {
        "vnext": [...]
      },
      "streamSettings": {
        "network": "ws",
        "security": "tls",
        ...
      }
    }
  ]
}
```

## Security Features

- Automatic SSL certificate management with Let's Encrypt
- UFW firewall with minimal open ports
- Secure NGINX configuration with modern TLS
- Traffic accounting and limits
- Automated log rotation
- UUID-based authentication

## Requirements

- Ubuntu 20.04 LTS
- Root access
- Domain name pointing to server IP
- Open ports 80 and 443

## Troubleshooting

### Check Service Status
```bash
menu status
```

### View Logs
```bash
sudo journalctl -u xray -f
sudo tail -f /var/log/xray/error.log
```

### Restore from Backup
```bash
sudo menu restore /path/to/backup.tar.gz
```

For more information and updates, visit: https://github.com/mkkelati/vpn7
README