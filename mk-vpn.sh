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
USE_SELF_SIGNED=false
USE_DIRECT_PORT=false

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
    if command -v dig >/dev/null 2>&1; then
        if ! dig +short "$domain" >/dev/null 2>&1; then
            log "WARN" "Domain $domain does not resolve. Continuing anyway..."
        fi
    elif command -v host >/dev/null 2>&1; then
        if ! host "$domain" >/dev/null 2>&1; then
            log "WARN" "Domain $domain does not resolve. Continuing anyway..."
        fi
    elif command -v nslookup >/dev/null 2>&1; then
        if ! nslookup "$domain" >/dev/null 2>&1; then
            log "WARN" "Domain $domain does not resolve. Continuing anyway..."
        fi
    else
        log "WARN" "No DNS lookup tools available, skipping domain resolution check"
    fi
}

# Check if port is available
check_port() {
    local port=$1
    local service_name=${2:-"Unknown"}
    
    # Use ss instead of netstat (more modern and commonly available)
    if command -v ss >/dev/null 2>&1; then
        local port_info
        port_info=$(ss -tuln | grep ":$port ")
        if [[ -n $port_info ]]; then
            log "WARN" "Port $port is already in use by $service_name"
            
            # If it's our own services, offer to restart
            if [[ $port == "443" ]] || [[ $port == "80" ]]; then
                read -p "Port $port is in use. Stop existing services and continue? (y/N): " stop_services
                if [[ $stop_services =~ ^[Yy] ]]; then
                    log "INFO" "Stopping existing services..."
                    systemctl stop nginx xray 2>/dev/null || true
                    pkill -f xray 2>/dev/null || true
                    sleep 2
                    
                    # Check again
                    port_info=$(ss -tuln | grep ":$port ")
                    if [[ -n $port_info ]]; then
                        error_exit "Port $port is still in use after stopping services"
                    fi
                    log "SUCCESS" "Port $port is now available"
                else
                    error_exit "Cannot continue with port $port in use"
                fi
            elif [[ $port == "10085" ]]; then
                log "INFO" "Xray port $port is in use, attempting to stop Xray service..."
                systemctl stop xray 2>/dev/null || true
                pkill -f xray 2>/dev/null || true
                sleep 2
                
                # Check again
                port_info=$(ss -tuln | grep ":$port ")
                if [[ -n $port_info ]]; then
                    error_exit "Port $port is still in use after stopping Xray"
                fi
                log "SUCCESS" "Port $port is now available"
            else
                error_exit "Port $port is already in use"
            fi
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
        chown xray:xray "$USER_DB_FILE" 2>/dev/null || true
        log "INFO" "Initialized user database"
    fi
}

# Check for incomplete installation
check_incomplete_installation() {
    local has_xray=false
    local has_nginx_config=false
    local has_config_env=false
    local has_user_db=false
    
    # Check for existing components
    [[ -f /usr/local/bin/xray ]] && has_xray=true
    
    # Check for nginx configs (more robust)
    for config in "${NGINX_SITES_DIR}/"*; do
        if [[ -f "$config" ]] && [[ "$(basename "$config")" != "default" ]] && [[ "$(basename "$config")" != "default.bak" ]]; then
            has_nginx_config=true
            break
        fi
    done
    
    [[ -f "${XRAY_DATA_DIR}/config.env" ]] && has_config_env=true
    [[ -f "$USER_DB_FILE" ]] && has_user_db=true
    
    # If we have some components but not all, it's incomplete
    if [[ $has_xray == true ]] || [[ $has_nginx_config == true ]]; then
        log "INFO" "Detected existing MK VPN components"
        
        if [[ $has_config_env == false ]] || [[ $has_user_db == false ]]; then
            log "WARN" "Installation appears incomplete"
            print_color "$YELLOW" "Found existing installation that may be incomplete:"
            print_color "$CYAN" "  Xray binary: $(if [[ $has_xray == true ]]; then echo "✓ Found"; else echo "✗ Missing"; fi)"
            print_color "$CYAN" "  NGINX config: $(if [[ $has_nginx_config == true ]]; then echo "✓ Found"; else echo "✗ Missing"; fi)"
            print_color "$CYAN" "  Installation config: $(if [[ $has_config_env == true ]]; then echo "✓ Found"; else echo "✗ Missing"; fi)"
            print_color "$CYAN" "  User database: $(if [[ $has_user_db == true ]]; then echo "✓ Found"; else echo "✗ Missing"; fi)"
            echo
            
            read -p "What would you like to do? [1] Clean install [2] Try to complete [3] Cancel: " choice
            case $choice in
                1)
                    log "INFO" "Performing clean installation..."
                    cmd_cleanup_installation
                    return 0
                    ;;
                2)
                    log "INFO" "Attempting to complete installation..."
                    attempt_complete_installation
                    return 1
                    ;;
                *)
                    log "INFO" "Installation cancelled"
                    exit 0
                    ;;
            esac
        fi
    fi
    return 0
}

# Attempt to complete an incomplete installation
attempt_complete_installation() {
    log "INFO" "Attempting to complete incomplete installation..."
    
    # Try to find existing configuration
    local existing_domain=""
    local existing_ws_path=""
    local existing_xray_port=""
    local existing_ssl_type=""
    
    # Look for NGINX configs to extract info
    for config_file in "${NGINX_SITES_DIR}/"*; do
        if [[ -f "$config_file" ]] && [[ "$(basename "$config_file")" != "default" ]] && [[ "$(basename "$config_file")" != "default.bak" ]]; then
            existing_domain=$(basename "$config_file")
            existing_ws_path=$(grep -o 'location [^{]*' "$config_file" | head -n1 | awk '{print $2}' 2>/dev/null || echo "")
            if grep -q "self-signed" "$config_file" || grep -q "/etc/ssl/xray/" "$config_file"; then
                existing_ssl_type="self-signed"
            else
                existing_ssl_type="letsencrypt"
            fi
            break
        fi
    done
    
    # Look for Xray config to extract port
    if [[ -f "$XRAY_CONFIG_FILE" ]]; then
        existing_xray_port=$(jq -r '.inbounds[0].port // empty' "$XRAY_CONFIG_FILE" 2>/dev/null || echo "10085")
    fi
    
    # Set defaults if not found
    [[ -z "$existing_domain" ]] && existing_domain="localhost"
    [[ -z "$existing_ws_path" ]] && existing_ws_path="/$(openssl rand -hex 8)"
    [[ -z "$existing_xray_port" ]] && existing_xray_port="10085"
    [[ -z "$existing_ssl_type" ]] && existing_ssl_type="self-signed"
    
    # Create missing config.env
    if [[ ! -f "${XRAY_DATA_DIR}/config.env" ]]; then
        cat > "${XRAY_DATA_DIR}/config.env" << EOF
DOMAIN=${existing_domain}
WS_PATH=${existing_ws_path}
XRAY_PORT=${existing_xray_port}
USE_SELF_SIGNED=$(if [[ "$existing_ssl_type" == "self-signed" ]]; then echo "true"; else echo "false"; fi)
EOF
        log "SUCCESS" "Created missing config.env"
    fi
    
    # Create missing user database
    if [[ ! -f "$USER_DB_FILE" ]]; then
        echo '{"users": []}' > "$USER_DB_FILE"
        chmod 640 "$USER_DB_FILE"
        chown xray:xray "$USER_DB_FILE" 2>/dev/null || true
        log "SUCCESS" "Created missing user database"
    fi
    
    # Try to start services
    systemctl enable xray nginx 2>/dev/null || true
    systemctl start nginx xray 2>/dev/null || true
    
    log "SUCCESS" "Installation completion attempted"
    print_color "$GREEN" "Configuration recovered:"
    print_color "$CYAN" "  Domain: $existing_domain"
    print_color "$CYAN" "  WebSocket Path: $existing_ws_path"
    print_color "$CYAN" "  Xray Port: $existing_xray_port"
    print_color "$CYAN" "  SSL Type: $existing_ssl_type"
}

# Clean up incomplete installation
cmd_cleanup_installation() {
    log "INFO" "Cleaning up incomplete installation..."
    
    if [[ $DRY_RUN == true ]]; then
        log "INFO" "DRY RUN: Would clean up installation"
        return
    fi
    
    # Stop services
    systemctl stop xray nginx 2>/dev/null || true
    systemctl disable xray 2>/dev/null || true
    
    # Kill any remaining processes
    pkill -f xray 2>/dev/null || true
    
    # Remove files but keep user data
    rm -f /usr/local/bin/xray
    rm -f "${SYSTEMD_DIR}/xray.service"
    rm -rf "${NGINX_SITES_DIR}/"*.com "${NGINX_SITES_DIR}/"*.org "${NGINX_SITES_DIR}/"*.net 2>/dev/null || true
    rm -f /etc/nginx/sites-enabled/* 2>/dev/null || true
    
    # Remove SSL certificates but not Let's Encrypt ones
    rm -rf /etc/ssl/xray 2>/dev/null || true
    
    # Clean up config but preserve user database
    rm -f "${XRAY_DATA_DIR}/config.env" 2>/dev/null || true
    
    # Remove Xray config
    rm -f "$XRAY_CONFIG_FILE" 2>/dev/null || true
    
    # Reload systemd
    systemctl daemon-reload
    
    log "SUCCESS" "Cleanup completed - ready for fresh installation"
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
    local packages=("curl" "wget" "jq" "nginx" "certbot" "python3-certbot-nginx" "unzip" "socat" "ufw" "cron" "uuid-runtime" "net-tools" "dnsutils" "openssl")
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

# Generate Xray configuration for direct TLS handling
generate_xray_config_direct() {
    local uuid=$1
    local domain=$2
    local ws_path=$3
    local port=${4:-443}
    local cert_path="/etc/ssl/xray/cert.crt"
    local key_path="/etc/ssl/xray/private.key"
    
    if [[ $DRY_RUN == true ]]; then
        log "INFO" "DRY RUN: Would generate Xray direct TLS configuration"
        return
    fi
    
    # Generate self-signed certificate if using direct mode
    if [[ $USE_SELF_SIGNED == true ]]; then
        generate_self_signed_cert "$domain"
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
        "security": "tls",
        "tlsSettings": {
          "certificates": [
            {
              "certificateFile": "${cert_path}",
              "keyFile": "${key_path}"
            }
          ]
        },
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
        "security": "tls",
        "tlsSettings": {
          "certificates": [
            {
              "certificateFile": "${cert_path}",
              "keyFile": "${key_path}"
            }
          ]
        },
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
    "rules": []
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
    log "SUCCESS" "Xray direct TLS configuration generated"
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
    
    # Create initial HTTP-only configuration (SSL will be added later)
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

# Generate self-signed certificate
generate_self_signed_cert() {
    local domain=$1
    local cert_dir="/etc/ssl/xray"
    local server_ip
    server_ip=$(curl -s ifconfig.me || curl -s ipinfo.io/ip)
    
    if [[ $DRY_RUN == true ]]; then
        log "INFO" "DRY RUN: Would generate self-signed certificate"
        return
    fi
    
    log "INFO" "Generating self-signed certificate..."
    
    # Create certificate directory
    mkdir -p "$cert_dir"
    
    # Generate self-signed certificate
    openssl req -x509 -newkey rsa:2048 \
        -keyout "$cert_dir/private.key" \
        -out "$cert_dir/cert.crt" \
        -days 365 -nodes \
        -subj "/C=US/ST=State/L=City/O=XrayVPN/CN=${server_ip}" \
        -addext "subjectAltName=IP:${server_ip},DNS:${domain},DNS:localhost" \
        2>/dev/null
    
    # Set proper permissions
    chmod 600 "$cert_dir/private.key"
    chmod 644 "$cert_dir/cert.crt"
    chown root:root "$cert_dir"/*
    
    log "SUCCESS" "Self-signed certificate generated for IP: $server_ip"
    
    # Update NGINX configuration for self-signed SSL
    update_nginx_ssl_config "$domain" "$cert_dir"
}

# Update NGINX configuration for self-signed SSL
update_nginx_ssl_config() {
    local domain=$1
    local cert_dir=$2
    local site_config="${NGINX_SITES_DIR}/${domain}"
    local ws_path=$WS_PATH
    local xray_port=$XRAY_PORT
    
    if [[ $DRY_RUN == true ]]; then
        log "INFO" "DRY RUN: Would update NGINX SSL configuration"
        return
    fi
    
    log "INFO" "Updating NGINX configuration for SSL..."
    
    # Create HTTPS configuration
    cat > "$site_config" << EOF
server {
    listen 80;
    server_name ${domain};
    return 301 https://\$server_name\$request_uri;
}

server {
    listen 443 ssl http2;
    server_name ${domain};
    
    # Self-signed SSL configuration
    ssl_certificate ${cert_dir}/cert.crt;
    ssl_certificate_key ${cert_dir}/private.key;
    
    # Modern SSL configuration
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers ECDHE-RSA-AES128-GCM-SHA256:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-RSA-CHACHA20-POLY1305:ECDHE-RSA-AES128-SHA256:ECDHE-RSA-AES256-SHA384;
    ssl_prefer_server_ciphers off;
    ssl_session_cache shared:SSL:10m;
    ssl_session_timeout 10m;
    
    # Security headers
    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;
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
    
    # Test and reload NGINX
    if nginx -t; then
        systemctl reload nginx
        log "SUCCESS" "NGINX SSL configuration updated and reloaded"
    else
        log "ERROR" "NGINX configuration test failed"
        return 1
    fi
}

# Setup SSL with Let's Encrypt
setup_ssl() {
    local domain=$1
    
    if [[ $DRY_RUN == true ]]; then
        log "INFO" "DRY RUN: Would setup SSL for $domain"
        return
    fi
    
    if [[ $USE_SELF_SIGNED == true ]]; then
        generate_self_signed_cert "$domain"
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
    local domain_ip=""
    
    # Try different DNS lookup tools
    if command -v dig >/dev/null 2>&1; then
        domain_ip=$(dig +short "$domain" | head -n1 2>/dev/null)
    elif command -v host >/dev/null 2>&1; then
        domain_ip=$(host "$domain" | grep "has address" | head -n1 | awk '{print $4}' 2>/dev/null)
    elif command -v nslookup >/dev/null 2>&1; then
        domain_ip=$(nslookup "$domain" | grep -A1 "Name:" | tail -n1 | awk '{print $2}' 2>/dev/null)
    fi
    
    if [[ -z "$domain_ip" || "$server_ip" != "$domain_ip" ]]; then
        log "WARN" "Domain $domain (IP: $domain_ip) does not point to this server (IP: $server_ip)"
        log "INFO" "Would you like to use a self-signed certificate instead?"
        
        read -p "Use self-signed certificate? (Y/n): " use_self_signed
        if [[ ! $use_self_signed =~ ^[Nn] ]]; then
            USE_SELF_SIGNED=true
            generate_self_signed_cert "$domain"
            return
        fi
        
        log "WARN" "SSL certificate generation may fail. Please update your DNS records."
        read -p "Continue with Let's Encrypt anyway? (y/N): " continue_ssl
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
        log "INFO" "Falling back to self-signed certificate..."
        USE_SELF_SIGNED=true
        generate_self_signed_cert "$domain"
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
    local server_ip
    server_ip=$(curl -s ifconfig.me || curl -s ipinfo.io/ip)
    
    # Use server IP if self-signed certificate is used
    local connect_host="$domain"
    local insecure_param=""
    
    if [[ $USE_SELF_SIGNED == true ]]; then
        connect_host="$server_ip"
        insecure_param="&allowInsecure=1"
    fi
    
    case $protocol in
        "vless")
            echo "vless://${uuid}@${connect_host}:${port}?type=ws&security=tls&path=${ws_path}&host=${domain}&sni=${domain}${insecure_param}#${domain}_VLESS"
            ;;
        "vmess")
            local vmess_config
            vmess_config=$(jq -n \
                --arg add "$connect_host" \
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
                --argjson skip_cert_verify "$(if [[ $USE_SELF_SIGNED == true ]]; then echo true; else echo false; fi)" \
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
                    v: $v,
                    "skip-cert-verify": $skip_cert_verify
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
    local server_ip
    server_ip=$(curl -s ifconfig.me || curl -s ipinfo.io/ip)
    
    # Use server IP if self-signed certificate is used
    local connect_host="$domain"
    local tls_settings=""
    
    if [[ $USE_SELF_SIGNED == true ]]; then
        connect_host="$server_ip"
        tls_settings='"allowInsecure": true,'
    fi
    
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
            "address": "${connect_host}",
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
          ${tls_settings}
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
            "address": "${connect_host}",
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
          ${tls_settings}
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
    
    # Check for incomplete installation
    if ! check_incomplete_installation; then
        # Installation was completed, exit
        return 0
    fi
    
    create_directories
    
    # Install packages
    update_packages
    install_packages
    
    # Get configuration from user
    if [[ -z $DOMAIN ]]; then
        read -p "Enter your domain (e.g., example.com): " DOMAIN
    fi
    validate_domain "$DOMAIN"
    
    # Ask about SSL certificate type
    if [[ $USE_SELF_SIGNED == false ]]; then
        echo
        print_color "$CYAN" "SSL Certificate Options:"
        print_color "$WHITE" "1. Let's Encrypt (free, requires valid domain)"
        print_color "$WHITE" "2. Self-signed (works immediately, any domain/IP)"
        echo
        read -p "Choose SSL option [1-2]: " ssl_choice
        
        case $ssl_choice in
            2)
                USE_SELF_SIGNED=true
                log "INFO" "Using self-signed certificates"
                ;;
            *)
                USE_SELF_SIGNED=false
                log "INFO" "Using Let's Encrypt certificates"
                ;;
        esac
        
        # Ask about port configuration
        echo
        print_color "$CYAN" "Port Configuration:"
        print_color "$WHITE" "1. Standard (NGINX proxy: clients→443→nginx→10085→xray)"
        print_color "$WHITE" "2. Direct (Xray handles TLS: clients→443→xray directly)"
        echo
        read -p "Choose port configuration [1-2]: " port_choice
        
        case $port_choice in
            2)
                USE_DIRECT_PORT=true
                log "INFO" "Using direct port 443 for Xray"
                ;;
            *)
                USE_DIRECT_PORT=false
                log "INFO" "Using NGINX reverse proxy configuration"
                ;;
        esac
    fi
    
    if [[ -z $WS_PATH ]]; then
        WS_PATH="/$(openssl rand -hex 8)"
        log "INFO" "Generated WebSocket path: $WS_PATH"
    fi
    
    if [[ -z $XRAY_PORT ]]; then
        if [[ $USE_DIRECT_PORT == true ]]; then
            XRAY_PORT=443
        else
            XRAY_PORT=10085
        fi
    fi
    check_port "$XRAY_PORT" "Xray"
    
    # Generate initial UUID
    local initial_uuid
    initial_uuid=$(generate_uuid)
    
    # Install and configure components
    install_xray
    create_xray_service
    if [[ $USE_DIRECT_PORT == true ]]; then
        generate_xray_config_direct "$initial_uuid" "$DOMAIN" "$WS_PATH" "$XRAY_PORT"
    else
        generate_xray_config "$initial_uuid" "$DOMAIN" "$WS_PATH" "$XRAY_PORT"
        configure_nginx "$DOMAIN" "$WS_PATH" "$XRAY_PORT"
        setup_ssl "$DOMAIN"
    fi
    configure_firewall
    setup_logrotate
    init_user_db
    
    # Start services
    if [[ $DRY_RUN == false ]]; then
        systemctl start xray
        if [[ $USE_DIRECT_PORT == false ]]; then
            systemctl reload nginx
        fi
    fi
    
    # Add initial user
    add_user_to_db "admin" "$initial_uuid" 0 0 "vless"
    
    # Save configuration
    cat > "${XRAY_DATA_DIR}/config.env" << EOF
DOMAIN=${DOMAIN}
WS_PATH=${WS_PATH}
XRAY_PORT=${XRAY_PORT}
USE_SELF_SIGNED=${USE_SELF_SIGNED}
USE_DIRECT_PORT=${USE_DIRECT_PORT}
EOF
    
    log "SUCCESS" "MK VPN installation completed successfully!"
    echo
    print_color "$GREEN" "=== Installation Summary ==="
    print_color "$CYAN" "Domain: $DOMAIN"
    print_color "$CYAN" "WebSocket Path: $WS_PATH"
    print_color "$CYAN" "Xray Port: $XRAY_PORT"
    print_color "$CYAN" "SSL Type: $(if [[ $USE_SELF_SIGNED == true ]]; then echo "Self-signed"; else echo "Let's Encrypt"; fi)"
    print_color "$CYAN" "Port Mode: $(if [[ $USE_DIRECT_PORT == true ]]; then echo "Direct (Xray handles TLS)"; else echo "Proxy (NGINX → Xray)"; fi)"
    print_color "$CYAN" "Admin UUID: $initial_uuid"
    echo
    print_color "$YELLOW" "Next steps:"
    if [[ $USE_SELF_SIGNED == true ]]; then
        print_color "$WHITE" "1. VPN is ready to use immediately with self-signed certificates"
        print_color "$WHITE" "2. Clients must enable 'Allow Insecure' or 'Skip Certificate Verification'"
        print_color "$WHITE" "3. Use 'mk-vpn add-user' to create client accounts"
        print_color "$WHITE" "4. Use 'mk-vpn status' to check system status"
    else
        print_color "$WHITE" "1. Ensure your domain points to this server's IP"
        print_color "$WHITE" "2. Use 'mk-vpn add-user' to create client accounts"
        print_color "$WHITE" "3. Use 'mk-vpn status' to check system status"
    fi
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
        print_color "$RED" "❌ Installation not found!"
        echo
        print_color "$YELLOW" "Available options:"
        print_color "$WHITE" "1. Run 'menu install' to install from scratch"
        print_color "$WHITE" "2. Use option 4 'Force Complete Installation' to fix"
        print_color "$WHITE" "3. Use option 5 'Quick Add User (Auto-fix)' instead"
        echo
        error_exit "Use one of the options above to fix the installation"
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

# Force complete installation - creates missing config files
cmd_force_complete_installation() {
    log "INFO" "Force completing MK VPN installation..."
    
    check_root
    
    print_color "$YELLOW" "This will attempt to complete your installation using existing components."
    echo
    
    # Check what exists
    local has_xray=false
    local has_nginx=false
    local has_cert=false
    
    [[ -f /usr/local/bin/xray ]] && has_xray=true
    systemctl is-active --quiet nginx && has_nginx=true
    [[ -f /etc/ssl/xray/cert.crt ]] && has_cert=true
    
    print_color "$CYAN" "Current Status:"
    print_color "$WHITE" "  Xray Binary: $(if [[ $has_xray == true ]]; then echo "✓ Found"; else echo "✗ Missing"; fi)"
    print_color "$WHITE" "  NGINX Service: $(if [[ $has_nginx == true ]]; then echo "✓ Running"; else echo "✗ Not running"; fi)"
    print_color "$WHITE" "  SSL Certificate: $(if [[ $has_cert == true ]]; then echo "✓ Found"; else echo "✗ Missing"; fi)"
    echo
    
    # Get configuration from user if missing
    local domain=""
    local ws_path=""
    local xray_port=""
    local use_self_signed="true"
    local use_direct_port="true"
    
    read -p "Enter your domain: " domain
    [[ -z "$domain" ]] && domain="localhost"
    
    read -p "Enter WebSocket path (or press Enter for random): " ws_path
    [[ -z "$ws_path" ]] && ws_path="/$(openssl rand -hex 8)"
    
    print_color "$CYAN" "SSL Certificate Type:"
    print_color "$WHITE" "1. Let's Encrypt"
    print_color "$WHITE" "2. Self-signed (recommended)"
    read -p "Choose [1-2]: " ssl_choice
    [[ "$ssl_choice" == "1" ]] && use_self_signed="false"
    
    print_color "$CYAN" "Port Configuration:"
    print_color "$WHITE" "1. NGINX Proxy (clients→443→nginx→10085→xray)"  
    print_color "$WHITE" "2. Direct TLS (clients→443→xray directly)"
    read -p "Choose [1-2]: " port_choice
    
    if [[ "$port_choice" == "1" ]]; then
        use_direct_port="false"
        xray_port="10085"
    else
        use_direct_port="true"
        xray_port="443"
    fi
    
    # Create directories
    create_directories
    
    # Install missing components
    if [[ $has_xray == false ]]; then
        log "INFO" "Installing Xray..."
        install_xray
        create_xray_service
    fi
    
    # Generate UUID
    local admin_uuid
    admin_uuid=$(generate_uuid)
    
    # Generate configuration
    if [[ "$use_direct_port" == "true" ]]; then
        generate_xray_config_direct "$admin_uuid" "$domain" "$ws_path" "$xray_port"
    else
        generate_xray_config "$admin_uuid" "$domain" "$ws_path" "$xray_port"
        configure_nginx "$domain" "$ws_path" "$xray_port"
        if [[ "$use_self_signed" == "true" ]]; then
            USE_SELF_SIGNED=true
            generate_self_signed_cert "$domain"
        fi
    fi
    
    # Create config file
    cat > "${XRAY_DATA_DIR}/config.env" << EOF
DOMAIN=${domain}
WS_PATH=${ws_path}
XRAY_PORT=${xray_port}
USE_SELF_SIGNED=${use_self_signed}
USE_DIRECT_PORT=${use_direct_port}
EOF
    
    # Initialize user database and add admin user
    init_user_db
    add_user_to_db "admin" "$admin_uuid" 0 0 "vless"
    
    # Start services
    systemctl enable xray nginx 2>/dev/null || true
    systemctl start xray
    if [[ "$use_direct_port" == "false" ]]; then
        systemctl start nginx
    fi
    
    log "SUCCESS" "Installation force completed!"
    echo
    print_color "$GREEN" "=== Configuration Summary ==="
    print_color "$CYAN" "Domain: $domain"
    print_color "$CYAN" "WebSocket Path: $ws_path"
    print_color "$CYAN" "Xray Port: $xray_port"
    print_color "$CYAN" "SSL Type: $(if [[ $use_self_signed == true ]]; then echo "Self-signed"; else echo "Let's Encrypt"; fi)"
    print_color "$CYAN" "Port Mode: $(if [[ $use_direct_port == true ]]; then echo "Direct TLS"; else echo "NGINX Proxy"; fi)"
    print_color "$CYAN" "Admin UUID: $admin_uuid"
    echo
    print_color "$YELLOW" "✨ You can now add users with option 2 or 5!"
}

# Quick add user with auto-fix missing configuration
cmd_quick_add_user() {
    log "INFO" "Quick add user with auto-fix..."
    
    # Check if config exists, if not try to create it
    if [[ ! -f "${XRAY_DATA_DIR}/config.env" ]]; then
        log "WARN" "Installation config missing, attempting auto-fix..."
        
        # Try to detect existing configuration
        local domain="localhost"
        local ws_path="/$(openssl rand -hex 8)"
        local xray_port="443"
        local use_self_signed="true"
        local use_direct_port="true"
        
        # Look for NGINX configs
        for config_file in "${NGINX_SITES_DIR}/"*; do
            if [[ -f "$config_file" ]] && [[ "$(basename "$config_file")" != "default" ]]; then
                domain=$(basename "$config_file")
                ws_path=$(grep -o 'location [^{]*' "$config_file" | head -n1 | awk '{print $2}' 2>/dev/null || echo "$ws_path")
                if grep -q "/etc/ssl/xray/" "$config_file"; then
                    use_self_signed="true"
                    use_direct_port="false"
                    xray_port="10085"
                fi
                break
            fi
        done
        
        # Look for Xray config
        if [[ -f "$XRAY_CONFIG_FILE" ]]; then
            local detected_port
            detected_port=$(jq -r '.inbounds[0].port // empty' "$XRAY_CONFIG_FILE" 2>/dev/null)
            if [[ -n "$detected_port" ]]; then
                xray_port="$detected_port"
                if [[ "$xray_port" == "443" ]]; then
                    use_direct_port="true"
                else
                    use_direct_port="false"
                fi
            fi
        fi
        
        # Create missing config
        cat > "${XRAY_DATA_DIR}/config.env" << EOF
DOMAIN=${domain}
WS_PATH=${ws_path}
XRAY_PORT=${xray_port}
USE_SELF_SIGNED=${use_self_signed}
USE_DIRECT_PORT=${use_direct_port}
EOF
        
        # Initialize user database if missing
        if [[ ! -f "$USER_DB_FILE" ]]; then
            init_user_db
        fi
        
        log "SUCCESS" "Auto-fixed configuration using detected settings"
        print_color "$CYAN" "Detected: Domain=$domain, WebSocket=$ws_path, Port=$xray_port"
    fi
    
    # Now proceed with normal user addition
    local name=""
    local expiry=30
    local limit=0
    local protocol="vless"
    
    read -p "Enter username: " name
    [[ -z "$name" ]] && error_exit "Username is required"
    
    read -p "Enter expiry days (default 30): " expiry_input
    [[ -n "$expiry_input" ]] && expiry="$expiry_input"
    
    read -p "Enter traffic limit in GB (0 for unlimited): " limit_input
    [[ -n "$limit_input" ]] && limit="$limit_input"
    
    # Check if user already exists
    if [[ -f "$USER_DB_FILE" ]] && jq -e ".users[] | select(.name == \"$name\")" "$USER_DB_FILE" >/dev/null 2>&1; then
        error_exit "User $name already exists"
    fi
    
    # Generate UUID and add user
    local uuid
    uuid=$(generate_uuid)
    
    # Load configuration
    source "${XRAY_DATA_DIR}/config.env"
    
    # Add user to database
    add_user_to_db "$name" "$uuid" "$expiry" "$limit" "$protocol"
    
    # Update Xray configuration if needed
    if [[ -f "$XRAY_CONFIG_FILE" ]]; then
        update_xray_config_user "$uuid" "$protocol"
    fi
    
    # Generate client configuration
    local server_ip
    server_ip=$(curl -s ifconfig.me || curl -s ipinfo.io/ip || echo "YOUR_SERVER_IP")
    
    local connect_host="$DOMAIN"
    local insecure_param=""
    local port=443
    
    if [[ $USE_SELF_SIGNED == true ]]; then
        connect_host="$server_ip"
        insecure_param="&allowInsecure=1"
    fi
    
    if [[ $USE_DIRECT_PORT == false ]]; then
        port=443  # NGINX proxy always uses 443
    else
        port=$XRAY_PORT  # Direct mode uses configured port
    fi
    
    local client_link="vless://${uuid}@${connect_host}:${port}?type=ws&security=tls&path=${WS_PATH}&host=${DOMAIN}&sni=${DOMAIN}${insecure_param}#${name}_VLESS"
    
    log "SUCCESS" "User $name added successfully!"
    echo
    print_color "$GREEN" "=== User Details ==="
    print_color "$CYAN" "Name: $name"
    print_color "$CYAN" "UUID: $uuid"
    print_color "$CYAN" "Protocol: $protocol"
    print_color "$CYAN" "Expires: $(if [[ $expiry -gt 0 ]]; then date -d "+${expiry} days" +"%Y-%m-%d"; else echo "Never"; fi)"
    print_color "$CYAN" "Traffic Limit: $(if [[ $limit -gt 0 ]]; then echo "${limit}GB"; else echo "Unlimited"; fi)"
    echo
    print_color "$GREEN" "=== 🔗 VLESS WebSocket + TLS Link ==="
    print_color "$YELLOW" "Copy this link to your VPN client:"
    echo
    print_color "$WHITE" "$client_link"
    echo
    if [[ $USE_SELF_SIGNED == true ]]; then
        print_color "$YELLOW" "⚠️  Important: Enable 'Allow Insecure' or 'Skip Certificate Verification' in your VPN client"
    fi
    echo
    print_color "$CYAN" "🎯 Quick Setup:"
    print_color "$WHITE" "1. Copy the link above"
    print_color "$WHITE" "2. Paste it in V2RayNG/V2RayN/Clash"
    print_color "$WHITE" "3. Enable 'Allow Insecure' if using self-signed certificates"
    print_color "$WHITE" "4. Connect and enjoy!"
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
    print_color "$WHITE" " 4) Force Complete Installation"
    print_color "$WHITE" " 5) Quick Add User (Auto-fix)"
    print_color "$WHITE" " 6) Renew User"
    print_color "$WHITE" " 7) Revoke User"
    print_color "$WHITE" " 8) Backup Configuration"
    print_color "$WHITE" " 9) Restore Configuration"
    print_color "$WHITE" "10) System Status"
    print_color "$WHITE" "11) Clean Installation"
    print_color "$WHITE" "12) Self Update"
    print_color "$WHITE" "13) Uninstall"
    print_color "$WHITE" " 0) Exit"
    echo
}

# Interactive menu
interactive_menu() {
    while true; do
        show_menu
        read -p "Enter your choice [0-13]: " choice
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
                cmd_force_complete_installation
                ;;
            5)
                cmd_quick_add_user
                ;;
            6)
                cmd_renew_user
                ;;
            7)
                cmd_revoke_user
                ;;
            8)
                cmd_backup
                ;;
            9)
                read -p "Enter backup file path: " backup_file
                cmd_restore "$backup_file"
                ;;
            10)
                cmd_status
                ;;
            11)
                cmd_cleanup_installation
                ;;
            12)
                cmd_self_update
                ;;
            13)
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
    force-complete                   - Force complete installation (creates missing config)
    quick-add-user                   - Add user with auto-fix (handles missing config)
    cleanup                          - Clean incomplete installation
    self-update                      - Update script to latest version
    uninstall                        - Remove MK VPN installation

ADD-USER OPTIONS:
    --name <name>                    - Username (required)
    --expiry <days>                  - Expiry in days (default: 30)
    --limit <GB>                     - Traffic limit in GB (default: unlimited)
    --protocol <vless|vmess>         - Protocol (default: vless)

GLOBAL OPTIONS:
    --dry-run                        - Show what would be done without executing
    --self-signed                    - Use self-signed certificates instead of Let's Encrypt
    --direct-port                    - Use Xray on port 443 directly (no NGINX proxy)
    --domain <domain>                - Set domain name
    --ws-path <path>                 - Set WebSocket path
    --xray-port <port>               - Set Xray port
    --help                           - Show this help message

EXAMPLES:
    # Install MK VPN with Let's Encrypt
    $0 install

    # Install MK VPN with self-signed certificates
    $0 install --self-signed

    # Install with Xray handling TLS directly on port 443
    $0 install --self-signed --direct-port

    # Add a user with 30-day expiry and 100GB limit
    $0 add-user --name john --expiry 30 --limit 100

    # List all users
    $0 list-users

    # Create backup
    $0 backup

    # Check status
    $0 status

    # Force complete installation (fix missing config)
    $0 force-complete

    # Quick add user with auto-fix
    $0 quick-add-user

    # Clean incomplete installation
    $0 cleanup

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
            --self-signed)
                USE_SELF_SIGNED=true
                shift
                ;;
            --direct-port)
                USE_DIRECT_PORT=true
                shift
                ;;
            install|add-user|list-users|revoke-user|renew-user|backup|restore|status|force-complete|quick-add-user|cleanup|uninstall|self-update)
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
        force-complete)
            cmd_force_complete_installation "$@"
            ;;
        quick-add-user)
            cmd_quick_add_user "$@"
            ;;
        cleanup)
            cmd_cleanup_installation "$@"
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