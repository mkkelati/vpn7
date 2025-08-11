# MK VPN Manager

A production-ready Bash script for managing Xray (xray-core) with WebSocket + TLS on Ubuntu 20.04. This script provides a complete solution for setting up and managing a secure VPN server with an intuitive command-line interface.

## 🚀 Quick Start

### One-Command Installation
```bash
wget -O /usr/local/bin/menu https://raw.githubusercontent.com/mkkelati/vpn7/main/mk-vpn.sh
chmod +x /usr/local/bin/menu
menu
```

### Interactive Menu
Simply run `menu` from anywhere to access the interactive management interface:
- Install VPN server
- Add/manage users
- View system status  
- Backup/restore configurations
- Self-update functionality

## 📋 Prerequisites

- **Ubuntu 20.04 LTS** (required)
- **Root access** (sudo privileges)
- **Domain name** pointing to your server's IP (optional with self-signed certificates)
- **Open ports** 80 and 443

## 🛠 Installation Process

1. **Run the installer**: `sudo menu install`
2. **Enter your domain**: e.g., `vpn.example.com` (or any name with self-signed)
3. **Choose SSL option**: Let's Encrypt (requires valid domain) or Self-signed (works immediately)
4. **Automatic setup**: SSL certificates, firewall, and Xray configuration
5. **Ready to use**: Add users and start connecting

## 🔐 SSL Certificate Options

### Let's Encrypt (Recommended for production)
- **Free and trusted** by all devices
- **Requires valid domain** pointing to your server
- **Automatic renewal** every 90 days
- **Best for public servers**

### Self-Signed Certificates
- **Works immediately** without domain setup
- **Perfect for testing** or private networks
- **Requires "Allow Insecure"** setting in VPN clients
- **No external dependencies**

## 🌐 Connection Modes

### Direct TLS Mode (Recommended)
- **Xray handles TLS directly** on port 443
- **Better performance** - no NGINX overhead
- **Automatic setcap configuration** for privileged port binding
- **Survives server reboots** via systemd service
- **Self-signed certificates supported**

### NGINX Proxy Mode
- **NGINX handles TLS** and proxies to Xray
- **Traditional reverse proxy setup**
- **Useful for complex routing scenarios**

```bash
# Install with self-signed certificates
sudo menu install --self-signed

# Or choose during installation
sudo menu install
```

## 👥 User Management

### Add a User
```bash
# Interactive prompt
menu add-user

# Command line with options
sudo menu add-user --name alice --expiry 90 --limit 500 --protocol vless
```

### List All Users
```bash
menu list-users
```
Shows username, UUID, protocol, creation date, expiry, and status.

### Manage Users
```bash
# Renew user for 60 more days
sudo menu renew-user --uuid <UUID> --days 60

# Revoke user access
sudo menu revoke-user --uuid <UUID>
```

## 📱 Client Configuration

After adding a user, you'll receive:

1. **Share Links** for mobile apps (V2RayNG, V2RayN)
2. **JSON configuration** for desktop clients
3. **Connection details** for manual setup

### Example VLESS Connection

**With Let's Encrypt:**
```
vless://uuid@domain.com:443?type=ws&security=tls&path=/randompath&host=domain.com&sni=domain.com#MyVPN_VLESS
```

**With Self-Signed Certificates:**
```
vless://uuid@SERVER_IP:443?type=ws&security=tls&path=/randompath&host=domain.com&sni=domain.com&allowInsecure=1#MyVPN_VLESS_SelfSigned
```

**Important:** For self-signed certificates, enable "Allow Insecure" or "Skip Certificate Verification" in your VPN client.

## 🔧 Management Commands

| Command | Description |
|---------|-------------|
| `menu install` | Full VPN server installation |
| `menu add-user` | Create new user account |
| `menu list-users` | Display all users |
| `menu force-complete` | Complete interrupted installation |
| `menu quick-add` | Auto-fix and add user |
| `menu fix-xray` | Troubleshoot and repair Xray service |
| `menu status` | System and service status |
| `menu backup` | Create configuration backup |
| `menu self-update` | Update to latest version |

## 🚀 New Recovery Features

### Automatic Installation Recovery
- **Detects incomplete installations** and offers completion
- **Force Complete Installation** (menu option 4) to retry failed setups
- **Quick Add User** (menu option 5) auto-detects existing config

### Comprehensive Troubleshooter
- **Fix Xray Service** (menu option 6) automatically diagnoses and repairs:
  - Missing GeoIP database files
  - Permission issues
  - Network capability problems (setcap)
  - Port conflicts
  - Service configuration errors

## 🔐 Security Features

- **Let's Encrypt SSL** with automatic renewal
- **UFW Firewall** with minimal attack surface
- **Secure NGINX** reverse proxy with modern TLS
- **Traffic monitoring** and usage limits
- **UUID-based authentication**
- **WebSocket camouflage** for enhanced privacy

## 📊 Monitoring & Maintenance

### System Status
```bash
menu status
```
View service health, SSL certificate expiry, user count, and system resources.

### Backup & Restore
```bash
# Create backup
sudo menu backup

# Restore from backup
sudo menu restore backup-file.tar.gz
```

## 🆘 Troubleshooting

### Common Issues
- **Domain not resolving**: Ensure A record points to server IP
- **SSL certificate issues**: Check domain accessibility on port 80
- **Connection problems**: Verify firewall and service status

### Debug Commands
```bash
# Check service logs
sudo journalctl -u xray -f

# Test configuration
sudo /usr/local/bin/xray -test -config /etc/xray/config.json

# Verify NGINX config
sudo nginx -t
```

## 🔄 Updates

The script includes automatic update functionality:
```bash
menu self-update
```

## 📝 License

MIT License - feel free to modify and distribute.

## 🤝 Contributing

Visit our GitHub repository for issues, feature requests, and contributions:
**https://github.com/mkkelati/vpn7**

---

**Note**: This script is designed for educational and legitimate privacy purposes. Users are responsible for compliance with local laws and regulations.