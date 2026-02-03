# fwctl - Universal Firewall Control Tool

A unified command-line tool for managing Linux firewalls, supporting **iptables**, **UFW**, and **Firewalld**.

## Features

- **Multi-backend Support**: Automatically detects and uses the best available firewall (firewalld > ufw > iptables)
- **Port Scanning**: Scan open ports with process information and blocking status
- **Interactive Mode**: Navigate and toggle port blocking with keyboard
- **Port Blocking**: Block ports while allowing specific IPs (whitelist)
- **Protected Ports**: SSH (22) and Nginx (80/443) are protected by default
- **Docker Compatible**: Works with Docker-exposed ports (iptables backend uses raw table PREROUTING)
- **Beautiful CLI**: Clean, colorful terminal output with aligned tables

## Installation

### Quick Install (Recommended)

```bash
curl -fsSL https://raw.githubusercontent.com/firshme/openthedoor/main/install.sh | sudo bash
```

This will automatically detect your architecture (x86_64/arm64) and install the appropriate binary.

### Manual Download

Download from [GitHub Releases](https://github.com/firshme/openthedoor/releases/tag/latest):

- **x86_64/amd64**: `fwctl-linux-amd64`
- **ARM64/aarch64**: `fwctl-linux-arm64`

```bash
# Example for x86_64
wget https://github.com/firshme/openthedoor/releases/download/latest/fwctl-linux-amd64
chmod +x fwctl-linux-amd64
sudo mv fwctl-linux-amd64 /usr/local/bin/fwctl
```

### Build from Source

```bash
# Clone the repository
git clone https://github.com/firshme/openthedoor.git
cd openthedoor

# Build
go build -o fwctl ./cmd/fwctl

# Install (optional)
sudo cp fwctl /usr/local/bin/
```

## Usage

### Scan Open Ports

```bash
fwctl scan
```

Output:
```
  ◆ Port Scan Results [Backend: iptables]

┌─────┬─────┬────────────┬───────┬─────────┬────────────────────────┐
│PORT │PROTO│PROCESS     │PID    │STATUS   │NOTE                    │
├─────┼─────┼────────────┼───────┼─────────┼────────────────────────┤
│22   │tcp  │sshd        │1234   │● OPEN   │Protected: SSH          │
│80   │tcp  │nginx       │5678   │● OPEN   │Protected: HTTP (Nginx) │
│3306 │tcp  │mysqld      │9012   │● BLOCKED│Allow: 10.0.0.1         │
│8080 │tcp  │docker-proxy│3456   │● OPEN   │                        │
└─────┴─────┴────────────┴───────┴─────────┴────────────────────────┘

  Total: 4 ports | ● 3 open | ● 1 blocked
```

### Interactive Mode

```bash
fwctl scan -i
```

- **↑/↓**: Navigate between ports
- **Space**: Toggle block/unblock
- **q**: Quit

### Block a Port

```bash
# Block port (localhost only)
fwctl block 3306

# Block port with allowed IPs
fwctl block 3306 --allow 10.0.0.1 --allow 192.168.1.100

# Force block protected port
fwctl block 22 --force --allow 10.0.0.1
```

### Allow IP Access

```bash
fwctl allow 3306 10.0.0.2
```

### Unblock a Port

```bash
fwctl unblock 3306
```

### List Rules

```bash
fwctl list
```

Output:
```
  ◆ Firewall Rules [Backend: iptables]
  ────────────────────────────────────────────────────────────

  PORT   PROTO  STATUS     ALLOWED IPs
  ────   ─────  ──────     ───────────
  3306   tcp    ● BLOCKED  10.0.0.1, 192.168.1.100
```

### Check Status

```bash
fwctl status
```

Output:
```
  ◆ Firewall Status
  ────────────────────────────────────────

  ● firewalld:   inactive  (0 rules)
  ● ufw:         inactive  (0 rules)
  ● iptables:    active    (2 rules)

  Default: iptables
```

### Specify Backend

```bash
fwctl --backend iptables scan
fwctl --backend ufw block 3306
fwctl --backend firewalld list
```

## How It Works

### Port Blocking Logic

When you block a port:
1. All external access is **denied by default**
2. **Localhost** (127.0.0.1) is always allowed
3. **Specified IPs** are added to the whitelist

### Backend Priority

fwctl automatically selects the firewall backend:

1. **If Docker is running** → Use **iptables** (best Docker compatibility)
2. **If no Docker** → Use first available: firewalld > ufw > iptables

### Protected Ports

The following ports are protected and require `--force` to block:
- **22** - SSH
- **80** - HTTP (Nginx)
- **443** - HTTPS (Nginx)

### Docker Support

For Docker-exposed ports, the iptables backend uses the **raw table PREROUTING** chain, which processes packets before NAT/Docker rules. This ensures fwctl can control Docker ports effectively.

## Backend-Specific Notes

### iptables (Recommended for Docker)
- Uses raw table PREROUTING for maximum priority
- Creates a custom chain `FWCTL` for rule management
- Best compatibility with Docker ports
- **Automatically selected when Docker is running**

### UFW (Recommended for non-Docker)
- Uses standard UFW commands
- Rules are persistent by default
- Full support for port blocking with IP whitelist

### Firewalld
- Uses rich rules for fine-grained control
- Relies on default deny behavior (no reject rules)
- Full support for port blocking with IP whitelist
- **Note**: For Docker ports, use iptables or map ports as `127.0.0.1:host:container`

## Requirements

- Linux operating system
- Root privileges (sudo)
- One of: iptables, ufw, or firewalld installed

## License

MIT License
