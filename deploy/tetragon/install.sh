#!/bin/bash
set -euo pipefail

# Philip - Tetragon Installation Helper
# Installs Tetragon as a systemd service on the CI/CD runner host.

echo "=== Philip: Installing Tetragon ==="
echo ""

# Check prerequisites
if [ "$(id -u)" -ne 0 ]; then
    echo "Error: This script must be run as root (sudo)"
    exit 1
fi

# Check kernel version (need 5.8+ for full eBPF support)
KERNEL_VERSION=$(uname -r | cut -d. -f1-2)
KERNEL_MAJOR=$(echo "$KERNEL_VERSION" | cut -d. -f1)
KERNEL_MINOR=$(echo "$KERNEL_VERSION" | cut -d. -f2)

if [ "$KERNEL_MAJOR" -lt 5 ] || ([ "$KERNEL_MAJOR" -eq 5 ] && [ "$KERNEL_MINOR" -lt 8 ]); then
    echo "Warning: Kernel version $KERNEL_VERSION detected. Tetragon works best with 5.8+."
    echo "Some features may not be available."
fi

echo "Kernel version: $(uname -r)"
echo ""

# Detect OS
if [ -f /etc/os-release ]; then
    . /etc/os-release
    OS=$ID
    OS_VERSION=$VERSION_ID
else
    echo "Error: Cannot detect OS"
    exit 1
fi

echo "Detected OS: $OS $OS_VERSION"
echo ""

# Install Tetragon based on OS
case "$OS" in
    ubuntu|debian)
        echo "Installing Tetragon via apt..."
        curl -sL https://github.com/cilium/tetragon/releases/latest/download/tetragon-linux-amd64.tar.gz \
            -o /tmp/tetragon.tar.gz
        tar -xzf /tmp/tetragon.tar.gz -C /usr/local/bin/ tetragon tetra
        rm /tmp/tetragon.tar.gz
        ;;
    rhel|centos|fedora|amzn)
        echo "Installing Tetragon from binary..."
        curl -sL https://github.com/cilium/tetragon/releases/latest/download/tetragon-linux-amd64.tar.gz \
            -o /tmp/tetragon.tar.gz
        tar -xzf /tmp/tetragon.tar.gz -C /usr/local/bin/ tetragon tetra
        rm /tmp/tetragon.tar.gz
        ;;
    *)
        echo "Unsupported OS: $OS. Installing from binary..."
        curl -sL https://github.com/cilium/tetragon/releases/latest/download/tetragon-linux-amd64.tar.gz \
            -o /tmp/tetragon.tar.gz
        tar -xzf /tmp/tetragon.tar.gz -C /usr/local/bin/ tetragon tetra
        rm /tmp/tetragon.tar.gz
        ;;
esac

# Create Tetragon config directory
mkdir -p /etc/tetragon/tetragon.conf.d/
mkdir -p /var/run/tetragon/

# Create systemd service for Tetragon
cat > /etc/systemd/system/tetragon.service << 'EOF'
[Unit]
Description=Tetragon eBPF Security Observability
Documentation=https://tetragon.io
After=network.target

[Service]
Type=simple
ExecStart=/usr/local/bin/tetragon --config-dir /etc/tetragon/tetragon.conf.d/
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF

# Enable and start Tetragon
systemctl daemon-reload
systemctl enable tetragon
systemctl start tetragon

echo ""
echo "=== Tetragon installed and running ==="
echo ""
echo "Verify with: tetra status"
echo ""

# Create Philip directories
mkdir -p /etc/philip
mkdir -p /var/run/philip

echo "=== Philip directories created ==="
echo "  Config: /etc/philip/"
echo "  Runtime: /var/run/philip/"
echo ""
echo "Next steps:"
echo "  1. Copy philip-agent binary to /usr/local/bin/"
echo "  2. Copy agent config to /etc/philip/agent.json"
echo "  3. Enable the Philip agent: systemctl enable --now philip-agent"
echo ""
