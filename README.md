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
- **Domain name** pointing to your server's IP
- **Open ports** 80 and 443

## 🛠 Installation Process

1. **Run the installer**: `sudo menu install`
2. **Enter your domain**: e.g., `vpn.example.com`
3. **Automatic setup**: SSL certificates, firewall, and Xray configuration
4. **Ready to use**: Add users and start connecting

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
```
vless://uuid@domain.com:443?type=ws&security=tls&path=/randompath&host=domain.com&sni=domain.com#MyVPN_VLESS
```

## 🔧 Management Commands

| Command | Description |
|---------|-------------|
| `menu install` | Full VPN server installation |
| `menu add-user` | Create new user account |
| `menu list-users` | Display all users |
| `menu status` | System and service status |
| `menu backup` | Create configuration backup |
| `menu self-update` | Update to latest version |

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