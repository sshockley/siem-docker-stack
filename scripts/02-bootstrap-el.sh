#!/bin/bash
# =============================================================================
# 02-bootstrap.sh — Install Podman, kernel tuning, prepare for SIEM stack
# =============================================================================
# Run on the SIEM server as root, AFTER 01-disk-setup.sh.
#
# What this script does:
#   1. Updates system packages and installs dependencies
#   2. Tunes kernel parameters for OpenSearch / SIEM workloads
#   3. Configures system limits (file descriptors, memlock)
#   4. Installs Podman with production-ready daemon config
#   5. Creates the deployment directory (default /opt/siem)
#   6. Configures UFW firewall for all SIEM service ports
#   7. Verifies data disks are mounted
# =============================================================================

set -euo pipefail

# Set SIEM_USER via env var or default to current user
#SIEM_USER="${SIEM_USER:-$(logname 2>/dev/null || echo "${SUDO_USER:-siem}")}"
SIEM_USER=1000
SIEM_GROUP=1000

# Set your deployment directory
DEPLOY_DIR="/opt/siem"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

echo -e "${CYAN}╔══════════════════════════════════════════╗${NC}"
echo -e "${CYAN}║  SIEM Server — System Bootstrap          ║${NC}"
echo -e "${CYAN}╚══════════════════════════════════════════╝${NC}"
echo ""

if [[ "$EUID" -ne 0 ]]; then
    echo -e "${RED}ERROR: Must run as root (sudo)${NC}"
    exit 1
fi

# ── System Updates ────────────────────────────────────────────────────────────
echo -e "${YELLOW}[1/7] Updating system packages...${NC}"
dnf upgrade -y
dnf install -y \
    curl wget gnupg2 \
    jq python3 python3-pip net-tools htop iotop \
    ca-certificates lsb-release gdisk
echo -e "${GREEN}✓ System updated${NC}"

# ── Kernel Tuning ─────────────────────────────────────────────────────────────
echo -e "${YELLOW}[2/7] Applying kernel tuning...${NC}"

cat > /etc/sysctl.d/99-siem.conf <<EOF
# OpenSearch requires vm.max_map_count >= 262144
# AL10 is already 1048576
# vm.max_map_count=262144

# Minimize swap usage (keep minimal swap for OOM safety)
vm.swappiness=1

# Network buffer tuning for high-volume syslog/log ingestion
net.core.rmem_max=33554432
net.core.rmem_default=16777216
net.core.wmem_max=33554432
net.core.netdev_max_backlog=5000

# File descriptor limits
# AL10 is already 9223372036854775807, might be enough
#fs.file-max=1048576

# Increase inotify watchers (for log file monitoring, Grafana, etc.)
fs.inotify.max_user_watches=524288
fs.inotify.max_user_instances=512
EOF

sysctl --system --quiet
echo -e "${GREEN}✓ Kernel tuning applied${NC}"

# ── System Limits ─────────────────────────────────────────────────────────────
echo -e "${YELLOW}[3/7] Configuring system limits...${NC}"

cat > /etc/security/limits.d/99-siem.conf <<EOF
# SIEM stack limits — required for OpenSearch memlock and file handles
* soft nofile 65536
* hard nofile 65536
* soft memlock unlimited
* hard memlock unlimited
* soft nproc 65536
* hard nproc 65536
EOF

echo -e "${GREEN}✓ System limits configured${NC}"

# ── Install Podman ────────────────────────────────────────────────────────────
echo -e "${YELLOW}[4/7] Installing Podman...${NC}"

if command -v podman &>/dev/null; then
    echo -e "${GREEN}✓ Podman already installed: $(podman --version)${NC}"
else
    # Skip cockpit-podman if you're not using cockpit
    dnf install -y \
        git \
        podman \
        podman-compose \
        podman-docker \
        cockpit-podman \
        podman-tui

#     # Production-ready Podman daemon config
#     mkdir -p /etc/podman
#     cat > /etc/podman/daemon.json <<EOF
# {
#     "log-driver": "json-file",
#     "log-opts": {
#         "max-size": "50m",
#         "max-file": "3"
#     },
#     "storage-driver": "overlay2",
#     "default-ulimits": {
#         "nofile": {
#             "Name": "nofile",
#             "Hard": 65536,
#             "Soft": 65536
#         },
#         "memlock": {
#             "Name": "memlock",
#             "Hard": -1,
#             "Soft": -1
#         }
#     }
# }
# EOF

    systemctl enable --now podman
    systemctl enable --now podman.socket
    echo -e "${GREEN}✓ Podman installed: $(podman --version)${NC}"
fi

# ── Deploy Directory ──────────────────────────────────────────────────────────
echo -e "${YELLOW}[5/7] Setting up deployment directory...${NC}"

mkdir -p "${DEPLOY_DIR}"
chown "${SIEM_USER}:${SIEM_GROUP}" "${DEPLOY_DIR}"

echo -e "${GREEN}✓ Deployment directory: ${DEPLOY_DIR}${NC}"

# ── Firewall ──────────────────────────────────────────────────────────────────
echo -e "${YELLOW}[6/7] Configuring firewalld...${NC}"

systemctl enable --now firewalld

# Log blocked packets
firewall-cmd --permanent --quiet --set-log-denied=unicast

# SSH (critical — don't lock yourself out!)
firewall-cmd --permanent --quiet --add-service ssh
firewall-cmd --reload --quiet

# SIEM Core Services
firewall-cmd --permanent --quiet --add-port=9200/tcp --set-description "OpenSearch HTTP"
firewall-cmd --permanent --quiet --add-port=5601/tcp --set-description "OpenSearch Dashboards"
firewall-cmd --permanent --quiet --add-port=3000/tcp --set-description "Grafana"
firewall-cmd --permanent --quiet --add-port=8086/tcp --set-description "InfluxDB"
firewall-cmd --permanent --quiet --add-port=9090/tcp --set-description "Prometheus"

# Wazuh
firewall-cmd --permanent --quiet --add-port=1514/udp --set-description "Wazuh agent"
firewall-cmd --permanent --quiet --add-port=1515/tcp --set-description "Wazuh agent enrollment"
firewall-cmd --permanent --quiet --add-port=55000/tcp --set-description "Wazuh API"
firewall-cmd --permanent --quiet --add-port=443/tcp --set-description "Wazuh dashboard"

# Log Ingestion
firewall-cmd --permanent --quiet --add-port=5140/udp --set-description "Logstash Suricata UDP"
firewall-cmd --permanent --quiet --add-port=5044/tcp --set-description "Logstash Beats"
firewall-cmd --permanent --quiet --add-port=514/udp --set-description "Syslog UDP"
firewall-cmd --permanent --quiet --add-port=514/tcp --set-description "Syslog TCP"

# Optional: Node Exporter (uncomment if using)
#firewall-cmd --permanent --quiet --add-port=9100/tcp --set-description "Node Exporter"

# Optional: Portainer (uncomment if using)
#firewall-cmd --permanent --quiet --add-port=9443/tcp --set-description "Portainer"

firewall-cmd --reload --quiet

echo -e "${GREEN}✓ Firewall configured${NC}"

# ── Verify Data Disks ────────────────────────────────────────────────────────
echo -e "${YELLOW}[7/7] Verifying data disks...${NC}"

# for mount in /data/hot /data/warm; do
#     if mountpoint -q "$mount"; then
#         echo -e "${GREEN}✓ ${mount} is mounted ($(df -h "$mount" | awk 'NR==2{print $2}'))${NC}"
#     else
#         echo -e "${RED}✗ ${mount} is NOT mounted — run 01-disk-setup.sh first!${NC}"
#         exit 1
#     fi
# done

# ── Summary ───────────────────────────────────────────────────────────────────
echo ""
echo -e "${GREEN}╔══════════════════════════════════════════╗${NC}"
echo -e "${GREEN}║  Bootstrap Complete                      ║${NC}"
echo -e "${GREEN}╚══════════════════════════════════════════╝${NC}"
echo ""
echo "System info:"
echo "  OS:        $(lsb_release -ds)"
echo "  Kernel:    $(uname -r)"
echo "  Podman:    $(podman --version 2>/dev/null | cut -d' ' -f3)"
echo "  RAM:       $(free -h | awk '/^Mem:/{print $2}')"
echo "  Hot disk:  $(df -h /data/hot | awk 'NR==2{print $4 " available"}')"
echo "  Warm disk: $(df -h /data/warm | awk 'NR==2{print $4 " available"}')"
echo ""
echo -e "${GREEN}Next: Run 03-deploy.sh to deploy the Podman stack${NC}"
echo ""
#echo -e "${YELLOW}NOTE: Log out and back in for podman group membership to take effect.${NC}"
