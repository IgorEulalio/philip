#!/usr/bin/env bash
# =============================================================================
# Philip EC2 Bootstrap
# =============================================================================
# Installs the Philip stack on an EC2 instance that already has a self-hosted
# GitHub Actions runner. No tokens or keys needed for a minimal setup.
#
# What this installs:
#   1. System dependencies (Docker, Docker Compose, Go, Git, protoc)
#   2. Tetragon (eBPF sensor)
#   3. Philip backend (docker-compose: Postgres + philip-server + Prometheus + Grafana)
#   4. Philip agent (systemd service)
#
# Supported OS:
#   - Amazon Linux 2 / Amazon Linux 2023
#   - Ubuntu / Debian
#   - Fedora / RHEL / CentOS / Rocky
#   - Arch Linux
#   - Any Linux with a supported package manager (dnf, yum, apt, pacman, zypper)
#   Kernel 5.8+ required for Tetragon.
#
# Prerequisites:
#   - Root / sudo access
#
# Usage:
#   sudo bash deploy/ec2-bootstrap.sh
#
# Optional (can add later by editing docker-compose env and restarting):
#   OPENAI_API_KEY       — enables L2 LLM triage
#   PHILIP_SLACK_WEBHOOK — enables Slack alerts
# =============================================================================
set -euo pipefail

if [ "$(id -u)" -ne 0 ]; then
    echo "ERROR: Run as root (sudo bash $0)"
    exit 1
fi

PHILIP_DIR="/opt/philip"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
# If running from the repo, use the repo root; otherwise clone
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

echo "=============================================="
echo " Philip Bootstrap (no keys needed)"
echo "=============================================="
echo ""

# ---------------------------------------------------------------------------
# Detect package manager
# ---------------------------------------------------------------------------
PKG_MGR=""
if command -v dnf &>/dev/null; then
    PKG_MGR="dnf"
elif command -v yum &>/dev/null; then
    PKG_MGR="yum"
elif command -v apt-get &>/dev/null; then
    PKG_MGR="apt"
elif command -v pacman &>/dev/null; then
    PKG_MGR="pacman"
elif command -v zypper &>/dev/null; then
    PKG_MGR="zypper"
else
    echo "ERROR: No supported package manager found (dnf, yum, apt, pacman, zypper)."
    exit 1
fi
echo "    Package manager: ${PKG_MGR}"

# ---------------------------------------------------------------------------
# 1. System packages
# ---------------------------------------------------------------------------
echo ">>> [1/6] Installing system packages..."

install_packages() {
    case "${PKG_MGR}" in
        dnf)
            # Skip curl if curl-minimal is present (Amazon Linux 2023)
            DNF_PKGS="gcc gcc-c++ make git jq unzip ca-certificates tar gzip"
            if ! rpm -q curl-minimal &>/dev/null; then
                DNF_PKGS="${DNF_PKGS} curl"
            fi
            dnf install -y -q ${DNF_PKGS}
            ;;
        yum)
            YUM_PKGS="gcc gcc-c++ make git jq unzip ca-certificates tar gzip"
            if ! rpm -q curl-minimal &>/dev/null; then
                YUM_PKGS="${YUM_PKGS} curl"
            fi
            yum install -y -q ${YUM_PKGS}
            ;;
        apt)
            apt-get update -qq
            apt-get install -y -qq \
                build-essential curl git jq unzip ca-certificates > /dev/null
            ;;
        pacman)
            pacman -Sy --noconfirm --needed \
                base-devel curl git jq unzip ca-certificates
            ;;
        zypper)
            zypper install -y \
                gcc gcc-c++ make curl git jq unzip ca-certificates tar gzip
            ;;
    esac
}

install_docker() {
    if command -v docker &>/dev/null; then
        echo "    Docker already installed"
        return
    fi
    echo "    Installing Docker..."
    case "${PKG_MGR}" in
        dnf)
            dnf install -y -q dnf-plugins-core
            dnf config-manager --add-repo https://download.docker.com/linux/fedora/docker-ce.repo 2>/dev/null || true
            dnf install -y -q docker-ce docker-ce-cli containerd.io 2>/dev/null \
                || dnf install -y -q docker
            ;;
        yum)
            yum install -y -q docker
            ;;
        apt)
            apt-get install -y -qq docker.io > /dev/null
            ;;
        pacman)
            pacman -S --noconfirm docker
            ;;
        zypper)
            zypper install -y docker
            ;;
    esac
}

install_docker_compose() {
    if command -v docker-compose &>/dev/null; then
        echo "    Docker Compose already installed"
        return
    fi
    # docker compose v2 plugin ships with docker-ce on some distros
    if docker compose version &>/dev/null; then
        echo "    Docker Compose plugin detected, creating docker-compose wrapper..."
        cat > /usr/local/bin/docker-compose << 'WRAPPER'
#!/bin/sh
exec docker compose "$@"
WRAPPER
        chmod +x /usr/local/bin/docker-compose
        return
    fi
    echo "    Installing Docker Compose..."
    COMPOSE_VERSION=$(curl -s https://api.github.com/repos/docker/compose/releases/latest | grep '"tag_name"' | cut -d'"' -f4)
    curl -sL "https://github.com/docker/compose/releases/download/${COMPOSE_VERSION}/docker-compose-$(uname -s)-$(uname -m)" \
        -o /usr/local/bin/docker-compose
    chmod +x /usr/local/bin/docker-compose
}

install_packages
install_docker
systemctl enable --now docker
# Add the calling user to the docker group
REAL_USER="${SUDO_USER:-$(whoami)}"
usermod -aG docker "${REAL_USER}" 2>/dev/null || true
install_docker_compose
echo "    $(docker --version)"
echo "    $(docker-compose version 2>/dev/null || docker-compose --version)"

# Install Go (all platforms)
GO_VERSION="1.25.4"
if ! command -v go &>/dev/null || ! go version | grep -q "go1.25"; then
    echo "    Installing Go ${GO_VERSION}..."
    rm -rf /usr/local/go
    curl -sL "https://go.dev/dl/go${GO_VERSION}.linux-amd64.tar.gz" | tar -C /usr/local -xzf -
fi
export PATH="/usr/local/go/bin:${PATH}"
echo 'export PATH="/usr/local/go/bin:${PATH}"' > /etc/profile.d/go.sh
echo "    $(go version)"

# Install protoc (all platforms)
PROTOC_VERSION="28.3"
if ! command -v protoc &>/dev/null; then
    echo "    Installing protoc ${PROTOC_VERSION}..."
    curl -sL "https://github.com/protocolbuffers/protobuf/releases/download/v${PROTOC_VERSION}/protoc-${PROTOC_VERSION}-linux-x86_64.zip" \
        -o /tmp/protoc.zip
    unzip -o /tmp/protoc.zip -d /usr/local bin/protoc 'include/*' > /dev/null
    rm /tmp/protoc.zip
fi
echo "    $(protoc --version)"

# Install Go protoc plugins
go install google.golang.org/protobuf/cmd/protoc-gen-go@latest
go install google.golang.org/grpc/cmd/protoc-gen-go-grpc@latest
export PATH="$(go env GOPATH)/bin:${PATH}"
echo "    protoc-gen-go installed"

# ---------------------------------------------------------------------------
# 2. Install Tetragon
# ---------------------------------------------------------------------------
echo ">>> [2/6] Installing Tetragon..."

KERNEL_MAJOR=$(uname -r | cut -d. -f1)
KERNEL_MINOR=$(uname -r | cut -d. -f2)
if [ "$KERNEL_MAJOR" -lt 5 ] || ([ "$KERNEL_MAJOR" -eq 5 ] && [ "$KERNEL_MINOR" -lt 8 ]); then
    echo "    WARNING: Kernel $(uname -r) — Tetragon needs 5.8+."
fi

if ! command -v tetragon &>/dev/null; then
    TETRAGON_VERSION="v1.3.0"
    curl -sL "https://github.com/cilium/tetragon/releases/download/${TETRAGON_VERSION}/tetragon-${TETRAGON_VERSION}-amd64.tar.gz" \
        -o /tmp/tetragon.tar.gz
    mkdir -p /tmp/tetragon-extract
    tar -xzf /tmp/tetragon.tar.gz -C /tmp/tetragon-extract
    find /tmp/tetragon-extract -name "tetragon" -type f -executable -exec cp {} /usr/local/bin/tetragon \;
    find /tmp/tetragon-extract -name "tetra" -type f -executable -exec cp {} /usr/local/bin/tetra \; 2>/dev/null || true
    rm -rf /tmp/tetragon.tar.gz /tmp/tetragon-extract
    chmod +x /usr/local/bin/tetragon
    echo "    Tetragon binary installed"
else
    echo "    Tetragon already installed, skipping download"
fi

mkdir -p /etc/tetragon/tetragon.conf.d /var/run/tetragon

cat > /etc/systemd/system/tetragon.service << 'UNIT'
[Unit]
Description=Tetragon eBPF Security Observability
After=network.target

[Service]
Type=simple
ExecStart=/usr/local/bin/tetragon --config-dir /etc/tetragon/tetragon.conf.d/
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
UNIT

systemctl daemon-reload
systemctl enable --now tetragon
echo "    Tetragon service running"

# ---------------------------------------------------------------------------
# 3. Build Philip binaries
# ---------------------------------------------------------------------------
echo ">>> [3/6] Building Philip..."

cd "${REPO_ROOT}"

echo "    Generating proto..."
make proto

echo "    Compiling binaries..."
go build -ldflags="-s -w" -o bin/philip-agent  ./agent/cmd/philip-agent
go build -ldflags="-s -w" -o bin/philip-server  ./backend/cmd/philip-server
go build -ldflags="-s -w" -o bin/philip         ./backend/cmd/philip-cli

cp bin/philip-agent  /usr/local/bin/
cp bin/philip-server /usr/local/bin/
cp bin/philip        /usr/local/bin/
echo "    Binaries: philip-agent, philip-server, philip"

# ---------------------------------------------------------------------------
# 4. Start Philip backend (docker-compose)
# ---------------------------------------------------------------------------
echo ">>> [4/6] Starting backend (Postgres + philip-server)..."

cd "${REPO_ROOT}/deploy"
docker-compose up -d --build

echo -n "    Waiting for health..."
for i in $(seq 1 30); do
    if curl -sf http://localhost:8080/health > /dev/null 2>&1; then
        echo " OK"
        break
    fi
    [ "$i" -eq 30 ] && echo " TIMEOUT — check: docker-compose logs"
    echo -n "."
    sleep 2
done

# ---------------------------------------------------------------------------
# 5. Configure & start Philip agent
# ---------------------------------------------------------------------------
echo ">>> [5/6] Starting Philip agent..."

mkdir -p /etc/philip /var/run/philip
chmod 777 /var/run/philip  # runner user needs socket access

cat > /etc/philip/agent.json << 'CFG'
{
  "sensor": {
    "type": "tetragon",
    "tetragon_address": "unix:///var/run/tetragon/tetragon.sock"
  },
  "backend": {
    "address": "localhost:9090",
    "heartbeat_interval_seconds": 30
  },
  "runner": {
    "process_name": "Runner.Worker",
    "max_events_per_job": 100000
  },
  "action_socket_path": "/var/run/philip/action.sock",
  "log_level": "info"
}
CFG

# Copy Tetragon tracing policies
cp "${REPO_ROOT}"/agent/sensor/tetragon/policies/*.yaml /etc/tetragon/tetragon.conf.d/ 2>/dev/null || true

# Install systemd service
cp "${REPO_ROOT}/deploy/systemd/philip-agent.service" /etc/systemd/system/
systemctl daemon-reload
systemctl enable --now philip-agent
echo "    Agent running"

# ---------------------------------------------------------------------------
# 6. Verify
# ---------------------------------------------------------------------------
echo ""
echo ">>> [6/6] Verification"
echo "----------------------------------------------"

check() {
    if systemctl is-active --quiet "$1" 2>/dev/null; then
        echo "  [OK]   $1"
    else
        echo "  [FAIL] $1"
    fi
}

check tetragon
check philip-agent

docker ps --format '{{.Names}}' | grep -q philip-server \
    && echo "  [OK]   philip-server (docker)" \
    || echo "  [FAIL] philip-server (docker)"

docker ps --format '{{.Names}}' | grep -q postgres \
    && echo "  [OK]   postgres (docker)" \
    || echo "  [FAIL] postgres (docker)"

docker ps --format '{{.Names}}' | grep -q prometheus \
    && echo "  [OK]   prometheus (docker)" \
    || echo "  [FAIL] prometheus (docker)"

docker ps --format '{{.Names}}' | grep -q grafana \
    && echo "  [OK]   grafana (docker)" \
    || echo "  [FAIL] grafana (docker)"

curl -sf http://localhost:8080/health > /dev/null 2>&1 \
    && echo "  [OK]   REST API (localhost:8080)" \
    || echo "  [FAIL] REST API (localhost:8080)"

# Check if a GHA runner is running
systemctl list-units --type=service --state=running 2>/dev/null | grep -q "actions.runner" \
    && echo "  [OK]   github-actions-runner" \
    || echo "  [WARN] github-actions-runner not detected as systemd service"

echo "----------------------------------------------"
echo ""
echo "Philip is installed. Next steps:"
echo ""
echo "  1. Push the repo (with .github/workflows/philip-e2e.yml) to GitHub"
echo "  2. From your local machine (with gh CLI):"
echo "     bash deploy/run-e2e-test.sh --baseline   # train baseline (12 runs)"
echo "     bash deploy/run-e2e-test.sh --attack      # simulate attack"
echo "     bash deploy/run-e2e-test.sh --status      # check findings"
echo ""
echo "Logs:"
echo "  journalctl -u philip-agent -f"
echo "  journalctl -u tetragon -f"
echo "  docker-compose -f ${REPO_ROOT}/deploy/docker-compose.yml logs -f"
echo ""
