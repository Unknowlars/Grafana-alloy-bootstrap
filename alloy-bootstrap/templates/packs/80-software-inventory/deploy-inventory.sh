#!/bin/bash
# =============================================================================
# Linux Software Inventory — All-in-One Installer
# =============================================================================
# Self-contained deployment script. Does everything the Ansible role does:
#   1. Installs dependencies (jq, openssl)
#   2. Creates directories
#   3. Deploys linux_inventory.sh + eol-products.conf
#   4. Fetches full EOL dump from endoflife.date API
#   5. Sets up cron (every 6 hours)
#   6. Runs initial collection
#
# Usage:
#   curl -sL <url>/deploy-inventory.sh | sudo bash
#   # or
#   chmod +x deploy-inventory.sh
#   sudo ./deploy-inventory.sh
#
# Options:
#   --no-cron       Skip cron job creation
#   --no-fetch      Skip EOL API fetch (use if no internet — deploy cache later)
#   --no-run        Skip initial inventory run
#   --uninstall     Remove everything
#   --dir <path>    Override install directory (default: /data/software/application_scripts/software_inventory)
#   --cron <expr>   Override cron schedule (default: "0 */6 * * *")
#
# Supports: RHEL, Oracle Linux, Rocky, Alma, CentOS, Fedora, Debian, Ubuntu, SUSE
# =============================================================================

set -euo pipefail

# --- Defaults ---
INSTALL_DIR="/data/software/application_scripts/software_inventory"
TEXTFILE_DIR="/var/lib/prometheus/node-exporter"
CRON_SCHEDULE="0 */6 * * *"
EOL_API_URL="https://endoflife.date/api/v1/products/full"
DO_CRON=true
DO_FETCH=true
DO_RUN=true
DO_UNINSTALL=false

# --- Colors ---
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
NC='\033[0m'

log()  { echo -e "${GREEN}[✓]${NC} $1"; }
warn() { echo -e "${YELLOW}[!]${NC} $1"; }
err()  { echo -e "${RED}[✗]${NC} $1"; }
info() { echo -e "${BLUE}[→]${NC} $1"; }

# --- Parse arguments ---
while [[ $# -gt 0 ]]; do
    case "$1" in
        --no-cron)    DO_CRON=false; shift ;;
        --no-fetch)   DO_FETCH=false; shift ;;
        --no-run)     DO_RUN=false; shift ;;
        --uninstall)  DO_UNINSTALL=true; shift ;;
        --dir)        INSTALL_DIR="$2"; shift 2 ;;
        --cron)       CRON_SCHEDULE="$2"; shift 2 ;;
        -h|--help)
            echo "Usage: $0 [OPTIONS]"
            echo ""
            echo "Options:"
            echo "  --no-cron       Skip cron job creation"
            echo "  --no-fetch      Skip EOL API fetch (deploy without internet)"
            echo "  --no-run        Skip initial inventory run"
            echo "  --uninstall     Remove everything"
            echo "  --dir <path>    Install directory (default: $INSTALL_DIR)"
            echo "  --cron <expr>   Cron schedule (default: \"$CRON_SCHEDULE\")"
            exit 0 ;;
        *) err "Unknown option: $1"; exit 1 ;;
    esac
done

# --- Root check ---
if [[ $EUID -ne 0 ]]; then
    err "This script must be run as root (or with sudo)."
    exit 1
fi

echo ""
echo "=============================================="
echo "  Linux Software Inventory — Installer"
echo "=============================================="
echo ""

# =================================================================
# UNINSTALL
# =================================================================
if [[ "$DO_UNINSTALL" == "true" ]]; then
    info "Uninstalling software inventory..."

    # Remove cron
    crontab -l 2>/dev/null | grep -v "linux_inventory.sh" | crontab - 2>/dev/null || true
    log "Removed cron job"

    # Remove prom file
    rm -f "${TEXTFILE_DIR}/linux_inventory.prom"
    log "Removed Prometheus metrics file"

    # Remove install directory
    if [[ -d "$INSTALL_DIR" ]]; then
        rm -rf "$INSTALL_DIR"
        log "Removed $INSTALL_DIR"
    fi

    log "Uninstall complete."
    exit 0
fi

# =================================================================
# STEP 1: Install dependencies
# =================================================================
info "Installing dependencies..."

if command -v dnf &>/dev/null; then
    dnf install -y -q jq openssl 2>/dev/null
    log "Installed jq, openssl (dnf)"
elif command -v yum &>/dev/null; then
    yum install -y -q jq openssl 2>/dev/null
    log "Installed jq, openssl (yum)"
elif command -v apt-get &>/dev/null; then
    apt-get update -qq 2>/dev/null
    apt-get install -y -qq jq openssl 2>/dev/null
    log "Installed jq, openssl (apt)"
elif command -v zypper &>/dev/null; then
    zypper --non-interactive install jq openssl 2>/dev/null
    log "Installed jq, openssl (zypper)"
else
    warn "Unknown package manager — please install jq and openssl manually."
fi

# Verify jq is available
if ! command -v jq &>/dev/null; then
    err "jq is required but could not be installed. Please install it manually."
    exit 1
fi

# =================================================================
# STEP 2: Create directories
# =================================================================
info "Creating directories..."

mkdir -p "$INSTALL_DIR"
mkdir -p "$TEXTFILE_DIR"
chmod 755 "$INSTALL_DIR" "$TEXTFILE_DIR"

log "Created $INSTALL_DIR"
log "Created $TEXTFILE_DIR"

# =================================================================
# STEP 3: Deploy linux_inventory.sh
# =================================================================
info "Deploying linux_inventory.sh..."

cat > "${INSTALL_DIR}/linux_inventory.sh" << 'INVENTORY_SCRIPT_EOF'
#!/bin/bash
# =============================================================================
# Linux Software Inventory & System Info — Prometheus Metrics Generator
# =============================================================================
# Generates rich package metadata and system information in Prometheus
# textfile collector format for ingestion via node_exporter or Grafana Alloy.
#
# Supported distros:
#   RPM-based:    RHEL, Oracle Linux, CentOS, Rocky, AlmaLinux, Fedora, SUSE
#   DEB-based:    Ubuntu, Debian, Linux Mint, Pop!_OS, Proxmox
#
# Usage:
#   chmod +x linux_inventory.sh
#   ./linux_inventory.sh
#
# Cron (every 6 hours):
#   0 */6 * * * /usr/local/bin/linux_inventory.sh
#
# Prerequisites:
#   - Root/sudo privileges recommended (some metrics need it)
#   - Core:       bash >=4, coreutils, procps, gawk
#   - Commands:   lscpu, timedatectl, ss (or netstat)
#   - Packages:   rpm/dpkg (auto-detected)
#   - EOL checks: curl, jq, internet connectivity (optional, gracefully skipped)
#   - Security:   openssl (optional, for certificate scanning)
#
# Configuration files:
#   eol-products.conf  — custom EOL product tracking (same dir as script)
#
# =============================================================================

set -euo pipefail

# --- Configuration ---
TEXTFILE_COLLECTOR_DIR="/var/lib/prometheus/node-exporter"
OUTPUT_FILE="$TEXTFILE_COLLECTOR_DIR/linux_inventory.prom"
# Resolve script directory (so config + cache live alongside the script)
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CUSTOM_EOL_FILE="${SCRIPT_DIR}/eol-products.conf"
EOL_FULL_DUMP="${SCRIPT_DIR}/eol-full.json"   # single full API dump (preferred)
EOL_CACHE_DIR="${SCRIPT_DIR}/eol-cache"        # per-product fallback cache
EOL_CACHE_MAX_AGE=86400   # 24 hours in seconds
EOL_API_BASE="https://endoflife.date/api/v1"   # v1 API
EOL_API_LEGACY="https://endoflife.date/api"    # legacy API (per-product fallback)
EOL_TIMEOUT=10            # curl timeout per request in seconds
EOL_RETRIES=3             # number of curl retries per product

# --- Setup ---
mkdir -p "$TEXTFILE_COLLECTOR_DIR"
TMP_OUTPUT_FILE=$(mktemp)
TMP_EOL_FILE=$(mktemp)
chmod 644 "$TMP_OUTPUT_FILE" "$TMP_EOL_FILE"
trap 'rm -f "$TMP_OUTPUT_FILE" "$TMP_EOL_FILE"' EXIT

# --- Helper: escape Prometheus label values ---
prom_escape() {
    local val="$1"
    val="${val//\\/\\\\}"
    val="${val//\"/\\\"}"
    val="${val//$'\n'/\\n}"
    printf '%s' "$val"
}

# --- Helper: curl with retry and exponential backoff ---
curl_with_retry() {
    local url="$1"
    local output="$2"
    local attempt

    for attempt in $(seq 1 "$EOL_RETRIES"); do
        if curl -sf --max-time "$EOL_TIMEOUT" \
            -H "Accept: application/json" \
            "$url" -o "$output" 2>/dev/null; then
            return 0
        fi
        # Exponential backoff: 2s, 4s, 6s
        sleep $((attempt * 2))
    done
    return 1
}

# --- Helper: get version from package manager (preferred over command --version) ---
# Returns version string on stdout, returns 1 if not installed/found.
# Strips epoch, debian revision, and build metadata for clean version.
get_pkg_version() {
    local pkg_name="$1"
    local ver=""

    if [[ "$PKG_FAMILY" == "rpm" ]]; then
        ver=$(rpm -q --qf '%{VERSION}' "$pkg_name" 2>/dev/null) || return 1
        # rpm -q prints "package X is not installed" on failure
        [[ "$ver" == *"not installed"* ]] && return 1
        echo "$ver"
        return 0
    elif [[ "$PKG_FAMILY" == "deb" ]]; then
        ver=$(dpkg-query -W -f='${Version}' "$pkg_name" 2>/dev/null) || return 1
        [[ -z "$ver" ]] && return 1
        # Strip epoch (1:), debian revision (-3ubuntu2), build meta (+dfsg)
        ver="${ver#*:}"          # strip epoch
        ver="${ver%%-*}"         # strip debian revision (first -)
        ver="${ver%%+*}"         # strip build metadata
        ver="${ver%%~*}"         # strip tilde suffixes
        echo "$ver"
        return 0
    fi
    return 1
}

# --- Safe wrapper for commands that return non-zero on success ---
# dnf check-update returns 100 when updates are available
safe_run() {
    "$@" 2>/dev/null || true
}

# --- Detect OS Family ---
if [ -f /etc/os-release ]; then
    . /etc/os-release
    OS_ID="${ID:-unknown}"
    OS_NAME="${NAME:-unknown}"
    OS_VERSION="${VERSION_ID:-unknown}"
    OS_PRETTY="${PRETTY_NAME:-unknown}"
    OS_ID_LIKE="${ID_LIKE:-$OS_ID}"
else
    OS_ID="unknown"
    OS_NAME="unknown"
    OS_VERSION="unknown"
    OS_PRETTY="unknown"
    OS_ID_LIKE="unknown"
fi

# Determine package family
PKG_FAMILY=""
if command -v rpm &>/dev/null && command -v dnf &>/dev/null; then
    PKG_FAMILY="rpm"
    PKG_MGR="dnf"
elif command -v rpm &>/dev/null && command -v yum &>/dev/null; then
    PKG_FAMILY="rpm"
    PKG_MGR="yum"
elif command -v rpm &>/dev/null && command -v zypper &>/dev/null; then
    PKG_FAMILY="rpm"
    PKG_MGR="zypper"
elif command -v dpkg &>/dev/null && command -v apt &>/dev/null; then
    PKG_FAMILY="deb"
    PKG_MGR="apt"
elif command -v rpm &>/dev/null; then
    PKG_FAMILY="rpm"
    PKG_MGR="rpm"
elif command -v dpkg &>/dev/null; then
    PKG_FAMILY="deb"
    PKG_MGR="dpkg"
else
    echo "Error: No supported package manager found." >&2
    exit 1
fi


# =====================================================================
# SECTION 1: System Information
# =====================================================================

KERNEL_VERSION=$(uname -r)
KERNEL_ARCH=$(uname -m)
HOSTNAME_FULL=$(hostname -f 2>/dev/null || hostname)
HOSTNAME_SHORT=$(hostname -s 2>/dev/null || hostname)

# Uptime & last boot
BOOT_TIME=$(awk '/^btime/ {print $2}' /proc/stat 2>/dev/null || echo "0")
if [ "$BOOT_TIME" = "0" ]; then
    BOOT_TIME=$(date -d "$(uptime -s 2>/dev/null)" +%s 2>/dev/null || echo "0")
fi
UPTIME_SECONDS=$(awk '{printf "%.0f", $1}' /proc/uptime 2>/dev/null || echo "0")

# CPU info
CPU_MODEL=$(grep -m1 'model name' /proc/cpuinfo 2>/dev/null | cut -d: -f2 | sed 's/^ //' || echo "unknown")
CPU_CORES=$(nproc 2>/dev/null || grep -c ^processor /proc/cpuinfo 2>/dev/null || echo "0")
CPU_SOCKETS=$(lscpu 2>/dev/null | awk -F: '/^Socket\(s\)/ {gsub(/^ +/,"",$2); print $2}' || echo "1")
CPU_THREADS_PER_CORE=$(lscpu 2>/dev/null | awk -F: '/^Thread\(s\) per core/ {gsub(/^ +/,"",$2); print $2}' || echo "1")

# Memory info (in bytes)
MEM_TOTAL_KB=$(awk '/^MemTotal/ {print $2}' /proc/meminfo 2>/dev/null || echo "0")
MEM_TOTAL_BYTES=$((MEM_TOTAL_KB * 1024))
SWAP_TOTAL_KB=$(awk '/^SwapTotal/ {print $2}' /proc/meminfo 2>/dev/null || echo "0")
SWAP_TOTAL_BYTES=$((SWAP_TOTAL_KB * 1024))

# Disk — root filesystem size
ROOT_FS_SIZE=$(df -B1 / 2>/dev/null | awk 'NR==2 {print $2}' || echo "0")
ROOT_FS_USED=$(df -B1 / 2>/dev/null | awk 'NR==2 {print $3}' || echo "0")
ROOT_FS_AVAIL=$(df -B1 / 2>/dev/null | awk 'NR==2 {print $4}' || echo "0")
ROOT_FS_TYPE=$(df -T / 2>/dev/null | awk 'NR==2 {print $2}' || echo "unknown")

# SELinux / AppArmor status
SECURITY_FRAMEWORK="none"
SECURITY_STATUS="disabled"
if command -v getenforce &>/dev/null; then
    SECURITY_FRAMEWORK="selinux"
    SECURITY_STATUS=$(getenforce 2>/dev/null || echo "unknown")
elif command -v aa-status &>/dev/null; then
    SECURITY_FRAMEWORK="apparmor"
    if aa-enabled &>/dev/null 2>&1; then
        SECURITY_STATUS="enabled"
    else
        SECURITY_STATUS="disabled"
    fi
fi

# Virtualisation
VIRT_TYPE="bare-metal"
if command -v systemd-detect-virt &>/dev/null; then
    detected=$(systemd-detect-virt 2>/dev/null || true)
    if [ -n "$detected" ] && [ "$detected" != "none" ]; then
        VIRT_TYPE="$detected"
    fi
fi

# Timezone
TIMEZONE=$(timedatectl 2>/dev/null | awk -F: '/Time zone/ {gsub(/^ +/,"",$2); print $2}' | awk '{print $1}' || cat /etc/timezone 2>/dev/null || echo "unknown")

# NTP sync status (1=synced, 0=not synced)
NTP_SYNCED=0
if command -v timedatectl &>/dev/null; then
    if timedatectl status 2>/dev/null | grep -qiE '(NTP synchronized|System clock synchronized):\s*yes'; then
        NTP_SYNCED=1
    fi
fi

# Firewall status
FIREWALL="none"
FIREWALL_ACTIVE=0
if command -v firewall-cmd &>/dev/null; then
    FIREWALL="firewalld"
    if firewall-cmd --state &>/dev/null 2>&1; then
        FIREWALL_ACTIVE=1
    fi
elif command -v ufw &>/dev/null; then
    FIREWALL="ufw"
    if ufw status 2>/dev/null | grep -q "Status: active"; then
        FIREWALL_ACTIVE=1
    fi
elif command -v iptables &>/dev/null; then
    FIREWALL="iptables"
    rules=$(iptables -L -n 2>/dev/null | wc -l || echo "0")
    if [ "$rules" -gt 8 ]; then
        FIREWALL_ACTIVE=1
    fi
fi

# Needs reboot check
NEEDS_REBOOT=0
if [ -f /var/run/reboot-required ]; then
    # Debian/Ubuntu
    NEEDS_REBOOT=1
elif command -v needs-restarting &>/dev/null; then
    # RHEL/CentOS/Oracle — needs-restarting -r returns 1 if reboot needed
    if ! needs-restarting -r &>/dev/null 2>&1; then
        NEEDS_REBOOT=1
    fi
fi

# Services failed count (systemd)
FAILED_SERVICES=0
if command -v systemctl &>/dev/null; then
    FAILED_SERVICES=$(systemctl --state=failed --no-legend 2>/dev/null | wc -l || echo "0")
fi

# Users currently logged in
LOGGED_IN_USERS=$(who 2>/dev/null | wc -l || echo "0")

# Total local user accounts
TOTAL_USERS=$(awk -F: '$3 >= 1000 && $3 < 65534 {count++} END {print count+0}' /etc/passwd 2>/dev/null || echo "0")

# Write system info metrics
{
    echo "# HELP linux_system_info Static system information labels. Value is always 1."
    echo "# TYPE linux_system_info gauge"
    echo "linux_system_info{os_id=\"$(prom_escape "$OS_ID")\",os_name=\"$(prom_escape "$OS_NAME")\",os_version=\"$(prom_escape "$OS_VERSION")\",os_pretty=\"$(prom_escape "$OS_PRETTY")\",kernel=\"$(prom_escape "$KERNEL_VERSION")\",arch=\"$(prom_escape "$KERNEL_ARCH")\",hostname=\"$(prom_escape "$HOSTNAME_FULL")\",pkg_manager=\"$(prom_escape "$PKG_MGR")\",virt=\"$(prom_escape "$VIRT_TYPE")\",security_framework=\"$(prom_escape "$SECURITY_FRAMEWORK")\",security_status=\"$(prom_escape "$SECURITY_STATUS")\",timezone=\"$(prom_escape "$TIMEZONE")\",firewall=\"$(prom_escape "$FIREWALL")\"} 1"

    echo ""
    echo "# HELP linux_cpu_info CPU model information. Value is always 1."
    echo "# TYPE linux_cpu_info gauge"
    echo "linux_cpu_info{model=\"$(prom_escape "$CPU_MODEL")\",cores=\"$CPU_CORES\",sockets=\"$CPU_SOCKETS\",threads_per_core=\"$CPU_THREADS_PER_CORE\"} 1"

    echo ""
    echo "# HELP linux_boot_time_seconds Unix timestamp of last system boot."
    echo "# TYPE linux_boot_time_seconds gauge"
    echo "linux_boot_time_seconds $BOOT_TIME"

    echo ""
    echo "# HELP linux_uptime_seconds System uptime in seconds."
    echo "# TYPE linux_uptime_seconds gauge"
    echo "linux_uptime_seconds $UPTIME_SECONDS"

    echo ""
    echo "# HELP linux_memory_total_bytes Total physical memory in bytes."
    echo "# TYPE linux_memory_total_bytes gauge"
    echo "linux_memory_total_bytes $MEM_TOTAL_BYTES"

    echo ""
    echo "# HELP linux_swap_total_bytes Total swap space in bytes."
    echo "# TYPE linux_swap_total_bytes gauge"
    echo "linux_swap_total_bytes $SWAP_TOTAL_BYTES"

    echo ""
    echo "# HELP linux_rootfs_size_bytes Root filesystem total size in bytes."
    echo "# TYPE linux_rootfs_size_bytes gauge"
    echo "linux_rootfs_size_bytes{fstype=\"$ROOT_FS_TYPE\"} $ROOT_FS_SIZE"

    echo ""
    echo "# HELP linux_rootfs_used_bytes Root filesystem used space in bytes."
    echo "# TYPE linux_rootfs_used_bytes gauge"
    echo "linux_rootfs_used_bytes $ROOT_FS_USED"

    echo ""
    echo "# HELP linux_rootfs_avail_bytes Root filesystem available space in bytes."
    echo "# TYPE linux_rootfs_avail_bytes gauge"
    echo "linux_rootfs_avail_bytes $ROOT_FS_AVAIL"

    echo ""
    echo "# HELP linux_ntp_synced Whether the system clock is NTP synchronised. 1 = synced."
    echo "# TYPE linux_ntp_synced gauge"
    echo "linux_ntp_synced $NTP_SYNCED"

    echo ""
    echo "# HELP linux_firewall_active Whether the firewall is active. 1 = active."
    echo "# TYPE linux_firewall_active gauge"
    echo "linux_firewall_active{firewall=\"$FIREWALL\"} $FIREWALL_ACTIVE"

    echo ""
    echo "# HELP linux_reboot_required Whether the system requires a reboot. 1 = reboot needed."
    echo "# TYPE linux_reboot_required gauge"
    echo "linux_reboot_required $NEEDS_REBOOT"

    echo ""
    echo "# HELP linux_systemd_failed_units Number of failed systemd units."
    echo "# TYPE linux_systemd_failed_units gauge"
    echo "linux_systemd_failed_units $FAILED_SERVICES"

    echo ""
    echo "# HELP linux_logged_in_users Number of currently logged in user sessions."
    echo "# TYPE linux_logged_in_users gauge"
    echo "linux_logged_in_users $LOGGED_IN_USERS"

    echo ""
    echo "# HELP linux_local_user_accounts Number of local user accounts (UID >= 1000)."
    echo "# TYPE linux_local_user_accounts gauge"
    echo "linux_local_user_accounts $TOTAL_USERS"

} > "$TMP_OUTPUT_FILE"


# =====================================================================
# SECTION 2: Installed Packages  (CONSOLIDATED — single query per mgr)
# =====================================================================
# RPM:  ONE rpm -qa call emits all three metric types (info, install_time, size)
# DEB:  ONE dpkg-query call emits all three metric types
# This eliminates the redundant rpm -qa / dpkg-query calls from the old script
# that used to run three separate passes for the same data.
# =====================================================================

{
    echo ""
    echo "# HELP linux_installed_package Information about an installed package. Value is always 1."
    echo "# TYPE linux_installed_package gauge"
    echo ""
    echo "# HELP linux_package_install_time_seconds Unix timestamp when the package was installed."
    echo "# TYPE linux_package_install_time_seconds gauge"
    echo ""
    echo "# HELP linux_package_size_bytes Installed size of the package in bytes."
    echo "# TYPE linux_package_size_bytes gauge"
} >> "$TMP_OUTPUT_FILE"

package_count=0
total_size=0

declare -A repo_counts
declare -A vendor_counts
declare -A arch_counts
declare -A group_counts
oldest_install=""
newest_install=""

if [[ "$PKG_FAMILY" == "rpm" ]]; then
    # ---------------------------------------------------------------
    # RPM-based: SINGLE rpm -qa call + one dnf repoquery for repo info
    # All three metric types emitted in one consolidated pass.
    # ---------------------------------------------------------------

    # Build repo lookup map (one dnf call)
    declare -A REPO_MAP
    if [[ "$PKG_MGR" == "dnf" ]]; then
        while IFS=$'\t' read -r nevra repo; do
            [[ -n "$nevra" ]] && REPO_MAP["$nevra"]="$repo"
        done < <(dnf repoquery --installed --qf '%{name}-%{version}-%{release}.%{arch}\t%{from_repo}' 2>/dev/null)
    fi

    # SINGLE rpm query — every field we need in one pass
    while IFS=$'\t' read -r name version arch size installtime vendor group summary; do
        [[ -z "$name" ]] && continue

        nevra="${name}-${version}.${arch}"
        repo="${REPO_MAP[$nevra]:-unknown}"
        [[ "$repo" == "(none)" ]] && repo="unknown"

        [[ -z "$vendor" || "$vendor" == "(none)" ]] && vendor="unknown"
        [[ -z "$group" || "$group" == "(none)" || "$group" == "Unspecified" ]] && group="other"
        [[ -z "$summary" ]] && summary=""
        [[ -z "$installtime" || "$installtime" == "(none)" ]] && installtime="0"

        e_name=$(prom_escape "$name")
        e_version=$(prom_escape "$version")
        e_arch=$(prom_escape "$arch")
        e_repo=$(prom_escape "$repo")
        e_vendor=$(prom_escape "$vendor")
        e_group=$(prom_escape "$group")
        e_summary=$(prom_escape "$summary")

        # --- Metric 1: Package info ---
        echo "linux_installed_package{package=\"$e_name\",version=\"$e_version\",arch=\"$e_arch\",repo=\"$e_repo\",vendor=\"$e_vendor\",group=\"$e_group\",summary=\"$e_summary\",install_epoch=\"$installtime\"} 1"

        # --- Metric 2: Install time (skip if epoch 0) ---
        if [[ "$installtime" -gt 0 ]]; then
            echo "linux_package_install_time_seconds{package=\"$e_name\",version=\"$e_version\",arch=\"$e_arch\"} $installtime"
        fi

        # --- Metric 3: Package size ---
        echo "linux_package_size_bytes{package=\"$e_name\",version=\"$e_version\",arch=\"$e_arch\"} $size"

        # --- Aggregations ---
        ((package_count++)) || true
        ((total_size += size)) || true

        repo_counts["$repo"]=$(( ${repo_counts["$repo"]:-0} + 1 ))
        vendor_counts["$vendor"]=$(( ${vendor_counts["$vendor"]:-0} + 1 ))
        arch_counts["$arch"]=$(( ${arch_counts["$arch"]:-0} + 1 ))
        group_counts["$group"]=$(( ${group_counts["$group"]:-0} + 1 ))

        if [[ "$installtime" -gt 0 ]]; then
            [[ -z "$oldest_install" || "$installtime" -lt "$oldest_install" ]] && oldest_install="$installtime"
            [[ -z "$newest_install" || "$installtime" -gt "$newest_install" ]] && newest_install="$installtime"
        fi

    done < <(rpm -qa --qf '%{NAME}\t%{VERSION}-%{RELEASE}\t%{ARCH}\t%{SIZE}\t%{INSTALLTIME}\t%{VENDOR}\t%{GROUP}\t%{SUMMARY}\n') >> "$TMP_OUTPUT_FILE"

elif [[ "$PKG_FAMILY" == "deb" ]]; then
    # ---------------------------------------------------------------
    # DEB-based: SINGLE dpkg-query call, all three metrics in one pass
    # ---------------------------------------------------------------

    # Build origin/repo lookup from apt-cache policy (best effort, one call)
    declare -A DEB_REPO_MAP
    while IFS=$'\t' read -r pkg origin; do
        [[ -n "$pkg" ]] && DEB_REPO_MAP["$pkg"]="$origin"
    done < <(apt-cache policy $(dpkg-query -W -f='${Package}\n' 2>/dev/null) 2>/dev/null | awk '
        /^[a-zA-Z0-9]/ { pkg=$1; sub(/:$/,"",pkg) }
        /\*\*\*/ { getline; if ($0 ~ /http/ || $0 ~ /\//) { origin=$2; sub(/^.*\/\//,"",origin); sub(/\/.*/,"",origin); print pkg "\t" origin } }
    ' 2>/dev/null || true)

    # SINGLE dpkg-query — all fields in one pass
    while IFS=$'\t' read -r name version arch size_kb section maintainer summary; do
        [[ -z "$name" ]] && continue

        repo="${DEB_REPO_MAP[$name]:-unknown}"
        vendor="$maintainer"
        group="$section"
        size=$((size_kb * 1024))  # Convert KB to bytes

        [[ -z "$vendor" ]] && vendor="unknown"
        [[ -z "$group" ]] && group="other"
        [[ -z "$summary" ]] && summary=""

        # dpkg doesn't store install time — check /var/lib/dpkg/info/<pkg>.list mtime
        installtime="0"
        for listfile in "/var/lib/dpkg/info/${name}.list" "/var/lib/dpkg/info/${name}:${arch}.list"; do
            if [ -f "$listfile" ]; then
                installtime=$(stat -c %Y "$listfile" 2>/dev/null || echo "0")
                break
            fi
        done

        e_name=$(prom_escape "$name")
        e_version=$(prom_escape "$version")
        e_arch=$(prom_escape "$arch")
        e_repo=$(prom_escape "$repo")
        e_vendor=$(prom_escape "$vendor")
        e_group=$(prom_escape "$group")
        e_summary=$(prom_escape "$summary")

        # --- Metric 1: Package info ---
        echo "linux_installed_package{package=\"$e_name\",version=\"$e_version\",arch=\"$e_arch\",repo=\"$e_repo\",vendor=\"$e_vendor\",group=\"$e_group\",summary=\"$e_summary\",install_epoch=\"$installtime\"} 1"

        # --- Metric 2: Install time (skip if epoch 0) ---
        if [[ "$installtime" -gt 0 ]]; then
            echo "linux_package_install_time_seconds{package=\"$e_name\",version=\"$e_version\",arch=\"$e_arch\"} $installtime"
        fi

        # --- Metric 3: Package size ---
        echo "linux_package_size_bytes{package=\"$e_name\",version=\"$e_version\",arch=\"$e_arch\"} $size"

        # --- Aggregations ---
        ((package_count++)) || true
        ((total_size += size)) || true

        repo_counts["$repo"]=$(( ${repo_counts["$repo"]:-0} + 1 ))
        vendor_counts["$vendor"]=$(( ${vendor_counts["$vendor"]:-0} + 1 ))
        arch_counts["$arch"]=$(( ${arch_counts["$arch"]:-0} + 1 ))
        group_counts["$group"]=$(( ${group_counts["$group"]:-0} + 1 ))

        if [[ "$installtime" -gt 0 ]]; then
            [[ -z "$oldest_install" || "$installtime" -lt "$oldest_install" ]] && oldest_install="$installtime"
            [[ -z "$newest_install" || "$installtime" -gt "$newest_install" ]] && newest_install="$installtime"
        fi

    done < <(dpkg-query -W -f='${Package}\t${Version}\t${Architecture}\t${Installed-Size}\t${Section}\t${Maintainer}\t${binary:Summary}\n' 2>/dev/null) >> "$TMP_OUTPUT_FILE"
fi


# =====================================================================
# SECTION 3: Available Updates
# =====================================================================
{
    echo ""
    echo "# HELP linux_package_update_available Whether an update is available. 1 = update pending."
    echo "# TYPE linux_package_update_available gauge"
    echo ""
    echo "# HELP linux_package_update_security Whether a pending update is a security fix. 1 = security update."
    echo "# TYPE linux_package_update_security gauge"
} >> "$TMP_OUTPUT_FILE"

updates_total=0
security_total=0

if [[ "$PKG_MGR" == "dnf" ]]; then
    # All updates
    while IFS=$'\t' read -r name new_version arch; do
        [[ -z "$name" ]] && continue
        e_name=$(prom_escape "$name")
        e_new=$(prom_escape "$new_version")
        e_arch=$(prom_escape "$arch")
        echo "linux_package_update_available{package=\"$e_name\",new_version=\"$e_new\",arch=\"$e_arch\"} 1"
        ((updates_total++)) || true
    done < <(safe_run dnf check-update --quiet | awk 'NF>=3 && $1 !~ /^(Obsoleting|Security:)/ {
        split($1, a, "."); name=a[1]; arch=a[length(a)];
        print name "\t" $2 "\t" arch
    }') >> "$TMP_OUTPUT_FILE"

    # Security updates
    while IFS=$'\t' read -r name new_version arch; do
        [[ -z "$name" ]] && continue
        e_name=$(prom_escape "$name")
        e_new=$(prom_escape "$new_version")
        e_arch=$(prom_escape "$arch")
        echo "linux_package_update_security{package=\"$e_name\",new_version=\"$e_new\",arch=\"$e_arch\"} 1"
        ((security_total++)) || true
    done < <(safe_run dnf check-update --security --quiet | awk 'NF>=3 && $1 !~ /^(Obsoleting|Security:)/ {
        split($1, a, "."); name=a[1]; arch=a[length(a)];
        print name "\t" $2 "\t" arch
    }') >> "$TMP_OUTPUT_FILE"

elif [[ "$PKG_MGR" == "apt" ]]; then
    # Refresh apt cache silently (may need root)
    apt-get update -qq 2>/dev/null || true

    # All upgradable packages
    while IFS=$'\t' read -r name new_version arch; do
        [[ -z "$name" ]] && continue
        e_name=$(prom_escape "$name")
        e_new=$(prom_escape "$new_version")
        e_arch=$(prom_escape "$arch")
        echo "linux_package_update_available{package=\"$e_name\",new_version=\"$e_new\",arch=\"$e_arch\"} 1"
        ((updates_total++)) || true
    done < <(apt list --upgradable 2>/dev/null | grep -v "^Listing" | awk -F'[/ ]' '{print $1 "\t" $2 "\t" $3}') >> "$TMP_OUTPUT_FILE"

    # Security updates (from -security repos)
    while IFS=$'\t' read -r name new_version arch; do
        [[ -z "$name" ]] && continue
        e_name=$(prom_escape "$name")
        e_new=$(prom_escape "$new_version")
        e_arch=$(prom_escape "$arch")
        echo "linux_package_update_security{package=\"$e_name\",new_version=\"$e_new\",arch=\"$e_arch\"} 1"
        ((security_total++)) || true
    done < <(apt list --upgradable 2>/dev/null | grep -i "\-security" | awk -F'[/ ]' '{print $1 "\t" $2 "\t" $3}') >> "$TMP_OUTPUT_FILE"

elif [[ "$PKG_MGR" == "zypper" ]]; then
    while IFS='|' read -r _ name _ new_version arch _; do
        name=$(echo "$name" | xargs)
        new_version=$(echo "$new_version" | xargs)
        arch=$(echo "$arch" | xargs)
        [[ -z "$name" || "$name" == "Name" ]] && continue
        e_name=$(prom_escape "$name")
        e_new=$(prom_escape "$new_version")
        e_arch=$(prom_escape "$arch")
        echo "linux_package_update_available{package=\"$e_name\",new_version=\"$e_new\",arch=\"$e_arch\"} 1"
        ((updates_total++)) || true
    done < <(zypper --non-interactive list-updates 2>/dev/null) >> "$TMP_OUTPUT_FILE"

    while IFS='|' read -r _ name _ new_version arch _; do
        name=$(echo "$name" | xargs)
        new_version=$(echo "$new_version" | xargs)
        arch=$(echo "$arch" | xargs)
        [[ -z "$name" || "$name" == "Name" ]] && continue
        e_name=$(prom_escape "$name")
        e_new=$(prom_escape "$new_version")
        e_arch=$(prom_escape "$arch")
        echo "linux_package_update_security{package=\"$e_name\",new_version=\"$e_new\",arch=\"$e_arch\"} 1"
        ((security_total++)) || true
    done < <(zypper --non-interactive list-patches --category security 2>/dev/null) >> "$TMP_OUTPUT_FILE"
fi


# =====================================================================
# SECTION 4: Listening Services / Open Ports
# =====================================================================
{
    echo ""
    echo "# HELP linux_listening_port A TCP port the system is listening on. Value is always 1."
    echo "# TYPE linux_listening_port gauge"
} >> "$TMP_OUTPUT_FILE"

if command -v ss &>/dev/null; then
    ss -tlnp 2>/dev/null | awk 'NR>1 {
        split($4, addr, ":");
        port = addr[length(addr)];
        proc = $6;
        gsub(/.*"/, "", proc); gsub(/".*/, "", proc);
        if (port ~ /^[0-9]+$/) print port "\t" proc
    }' | sort -un -t$'\t' -k1,1 | while IFS=$'\t' read -r port process; do
        [[ -z "$port" ]] && continue
        echo "linux_listening_port{port=\"$port\",process=\"$(prom_escape "${process:-unknown}")\"} 1"
    done >> "$TMP_OUTPUT_FILE"
fi


# =====================================================================
# SECTION 5: Docker / Container Info (if available)
# =====================================================================
if command -v docker &>/dev/null && docker info &>/dev/null 2>&1; then
    {
        echo ""
        echo "# HELP linux_docker_info Docker engine information. Value is always 1."
        echo "# TYPE linux_docker_info gauge"
    } >> "$TMP_OUTPUT_FILE"

    DOCKER_VERSION=$(docker version --format '{{.Server.Version}}' 2>/dev/null || echo "unknown")
    DOCKER_CONTAINERS_RUNNING=$(docker info --format '{{.ContainersRunning}}' 2>/dev/null || echo "0")
    DOCKER_CONTAINERS_STOPPED=$(docker info --format '{{.ContainersStopped}}' 2>/dev/null || echo "0")
    DOCKER_IMAGES=$(docker info --format '{{.Images}}' 2>/dev/null || echo "0")

    {
        echo "linux_docker_info{version=\"$(prom_escape "$DOCKER_VERSION")\"} 1"

        echo ""
        echo "# HELP linux_docker_containers_running Number of running Docker containers."
        echo "# TYPE linux_docker_containers_running gauge"
        echo "linux_docker_containers_running $DOCKER_CONTAINERS_RUNNING"

        echo ""
        echo "# HELP linux_docker_containers_stopped Number of stopped Docker containers."
        echo "# TYPE linux_docker_containers_stopped gauge"
        echo "linux_docker_containers_stopped $DOCKER_CONTAINERS_STOPPED"

        echo ""
        echo "# HELP linux_docker_images_total Number of Docker images."
        echo "# TYPE linux_docker_images_total gauge"
        echo "linux_docker_images_total $DOCKER_IMAGES"
    } >> "$TMP_OUTPUT_FILE"
fi


# =====================================================================
# SECTION 6: Security Metrics
# =====================================================================
{
    echo ""
    echo "# HELP linux_suid_files_total Number of SUID files in system binary directories."
    echo "# TYPE linux_suid_files_total gauge"
    suid_count=$(find /usr/bin /usr/sbin /bin /sbin -type f -perm /4000 2>/dev/null | wc -l)
    echo "linux_suid_files_total $suid_count"

    echo ""
    echo "# HELP linux_sgid_files_total Number of SGID files in system binary directories."
    echo "# TYPE linux_sgid_files_total gauge"
    sgid_count=$(find /usr/bin /usr/sbin /bin /sbin -type f -perm /2000 2>/dev/null | wc -l)
    echo "linux_sgid_files_total $sgid_count"
} >> "$TMP_OUTPUT_FILE"

# --- SSL Certificate Monitoring ---
if command -v openssl &>/dev/null; then
    cert_count=0
    {
        echo ""
        echo "# HELP linux_ssl_certificate_expiry_days Days until SSL certificate expires. Negative = expired."
        echo "# TYPE linux_ssl_certificate_expiry_days gauge"

        now_epoch=$(date +%s)

        # Scan common certificate directories for real certificates
        while IFS= read -r cert_file; do
            # Skip CA bundles, symlinks, and trust stores to avoid noise
            [[ -L "$cert_file" ]] && continue
            [[ "$cert_file" == */ca-certificates* ]] && continue
            [[ "$cert_file" == */ca-bundle* ]] && continue
            [[ "$cert_file" == */trust/* ]] && continue
            [[ "$cert_file" == */anchors/* ]] && continue

            # Extract end date — skip if not a valid x509 cert
            end_date=$(openssl x509 -enddate -noout -in "$cert_file" 2>/dev/null | cut -d= -f2) || continue
            [[ -z "$end_date" ]] && continue

            end_epoch=$(date -d "$end_date" +%s 2>/dev/null) || continue
            days_remaining=$(( (end_epoch - now_epoch) / 86400 ))

            subject=$(openssl x509 -subject -noout -in "$cert_file" 2>/dev/null | sed 's/^subject[= ]*//' || echo "unknown")
            issuer=$(openssl x509 -issuer -noout -in "$cert_file" 2>/dev/null | sed 's/^issuer[= ]*//' || echo "unknown")

            echo "linux_ssl_certificate_expiry_days{path=\"$(prom_escape "$cert_file")\",subject=\"$(prom_escape "$subject")\",issuer=\"$(prom_escape "$issuer")\"} $days_remaining"
            ((cert_count++)) || true

        done < <(find /etc/ssl/certs /etc/ssl/private \
                      /etc/pki/tls/certs /etc/pki/tls/private \
                      /etc/letsencrypt/live \
                      /etc/nginx/ssl /etc/apache2/ssl /etc/httpd/ssl \
                      /etc/haproxy/ssl /etc/haproxy/certs \
                      /opt/certs /etc/certs \
                      -maxdepth 3 -type f \
                      \( -name "*.pem" -o -name "*.crt" -o -name "*.cer" \) \
                      2>/dev/null | head -100)  # cap at 100 to avoid runaway scans

        echo ""
        echo "# HELP linux_ssl_certificates_total Number of SSL certificates scanned."
        echo "# TYPE linux_ssl_certificates_total gauge"
        echo "linux_ssl_certificates_total $cert_count"

    } >> "$TMP_OUTPUT_FILE"
fi

# --- Journal errors (last 24h) ---
if command -v journalctl &>/dev/null; then
    journal_errors=$(journalctl --since "24 hours ago" --priority=err --no-pager -q 2>/dev/null | wc -l || echo "0")
    {
        echo ""
        echo "# HELP linux_journal_errors_24h Number of error-level journal entries in the last 24 hours."
        echo "# TYPE linux_journal_errors_24h gauge"
        echo "linux_journal_errors_24h $journal_errors"
    } >> "$TMP_OUTPUT_FILE"
fi


# =====================================================================
# SECTION 7: Summary / Aggregate Metrics
# =====================================================================
{
    echo ""
    echo "# HELP linux_inventory_packages_total Total number of installed packages."
    echo "# TYPE linux_inventory_packages_total gauge"
    echo "linux_inventory_packages_total $package_count"

    echo ""
    echo "# HELP linux_inventory_size_bytes_total Total installed size of all packages in bytes."
    echo "# TYPE linux_inventory_size_bytes_total gauge"
    echo "linux_inventory_size_bytes_total $total_size"

    echo ""
    echo "# HELP linux_inventory_oldest_install_seconds Epoch timestamp of the oldest installed package."
    echo "# TYPE linux_inventory_oldest_install_seconds gauge"
    echo "linux_inventory_oldest_install_seconds ${oldest_install:-0}"

    echo ""
    echo "# HELP linux_inventory_newest_install_seconds Epoch timestamp of the most recently installed package."
    echo "# TYPE linux_inventory_newest_install_seconds gauge"
    echo "linux_inventory_newest_install_seconds ${newest_install:-0}"

    echo ""
    echo "# HELP linux_inventory_packages_by_repo Number of packages from each repository."
    echo "# TYPE linux_inventory_packages_by_repo gauge"
    for repo in "${!repo_counts[@]}"; do
        echo "linux_inventory_packages_by_repo{repo=\"$(prom_escape "$repo")\"} ${repo_counts[$repo]}"
    done

    echo ""
    echo "# HELP linux_inventory_packages_by_vendor Number of packages from each vendor."
    echo "# TYPE linux_inventory_packages_by_vendor gauge"
    for vendor in "${!vendor_counts[@]}"; do
        echo "linux_inventory_packages_by_vendor{vendor=\"$(prom_escape "$vendor")\"} ${vendor_counts[$vendor]}"
    done

    echo ""
    echo "# HELP linux_inventory_packages_by_arch Number of packages per architecture."
    echo "# TYPE linux_inventory_packages_by_arch gauge"
    for arch in "${!arch_counts[@]}"; do
        echo "linux_inventory_packages_by_arch{arch=\"$(prom_escape "$arch")\"} ${arch_counts[$arch]}"
    done

    echo ""
    echo "# HELP linux_inventory_packages_by_group Number of packages per group/section."
    echo "# TYPE linux_inventory_packages_by_group gauge"
    for group in "${!group_counts[@]}"; do
        echo "linux_inventory_packages_by_group{group=\"$(prom_escape "$group")\"} ${group_counts[$group]}"
    done

    echo ""
    echo "# HELP linux_inventory_updates_available_total Total number of packages with available updates."
    echo "# TYPE linux_inventory_updates_available_total gauge"
    echo "linux_inventory_updates_available_total $updates_total"

    echo ""
    echo "# HELP linux_inventory_security_updates_total Total number of packages with security updates."
    echo "# TYPE linux_inventory_security_updates_total gauge"
    echo "linux_inventory_security_updates_total $security_total"

    echo ""
    echo "# HELP linux_inventory_last_update_seconds Unix timestamp of the last successful inventory run."
    echo "# TYPE linux_inventory_last_update_seconds gauge"
    echo "linux_inventory_last_update_seconds $(date +%s)"

    echo ""
    echo "# HELP linux_inventory_script_duration_seconds How long the inventory script took to run (before EOL)."
    echo "# TYPE linux_inventory_script_duration_seconds gauge"
    echo "linux_inventory_script_duration_seconds $SECONDS"

} >> "$TMP_OUTPUT_FILE"


# =============================================================================
# SECTION 8: End-of-Life (EOL) Checking via endoflife.date API
# =============================================================================
# Checks installed software against the endoflife.date lifecycle database.
# Requires: jq (gracefully skipped if missing).
#
# AUTO-MATCH MODE (when eol-full.json exists — pushed by Ansible):
#   1. Reads ALL ~430 products from the v1 full API dump
#   2. Scans every installed package (rpm -qa / dpkg -l)
#   3. Automatically matches installed packages → EOL products
#   4. No whitelist needed — if you install RabbitMQ tomorrow, it just works
#
# LEGACY MODE (no eol-full.json — per-product cache/API fallback):
#   Falls back to hardcoded detection of ~10 common products + command checks.
#
# Data source priority:
#   1. eol-full.json   — v1 full API dump  (auto-match, preferred)
#   2. eol-cache/*.json — per-product cache (legacy fallback)
#   3. Live API call    — if curl available (last resort)
#
# Override file: eol-products.conf  (in the same directory as this script)
#   - In auto-match mode: overrides/corrects auto-detected entries
#   - In legacy mode: adds products to the hardcoded list
#   - Format: product:cycle:label:version
#
# Browse all products: https://endoflife.date/
# =============================================================================

check_eol() {
    # jq is required for parsing — skip entirely if missing
    if ! command -v jq &>/dev/null; then
        echo "# linux_eol: skipped (jq not installed)" >> "$TMP_EOL_FILE"
        return 0
    fi

    # Determine data source
    local use_full_dump=false
    if [[ -f "$EOL_FULL_DUMP" ]]; then
        use_full_dump=true
    else
        # No full dump — need cache dir for per-product fallback
        mkdir -p "$EOL_CACHE_DIR" 2>/dev/null || return 0
    fi

    # =========================================================================
    # STEP 1: Build installed packages lookup (one rpm/dpkg call)
    # =========================================================================
    declare -A INSTALLED_PKGS   # package_name → version

    if [[ "$PKG_FAMILY" == "rpm" ]]; then
        while IFS=$'\t' read -r pkg ver; do
            [[ -n "$pkg" ]] && INSTALLED_PKGS["$pkg"]="$ver"
        done < <(rpm -qa --qf '%{NAME}\t%{VERSION}\n')
    elif [[ "$PKG_FAMILY" == "deb" ]]; then
        while IFS=$'\t' read -r pkg ver; do
            [[ -n "$pkg" ]] && INSTALLED_PKGS["$pkg"]="$ver"
        done < <(dpkg-query -W -f='${Package}\t${Version}\n' 2>/dev/null)
    fi

    # =========================================================================
    # STEP 2: Product slug → package candidate mapping
    # =========================================================================
    # For products where the endoflife.date slug doesn't match the package name.
    # Space-separated candidate package names — first match wins.
    # Products NOT in this map default to: "slug" and "slug-server".
    declare -A PKG_CANDIDATES

    # Containers & orchestration
    PKG_CANDIDATES["docker-engine"]="docker-ce docker-engine docker.io"
    PKG_CANDIDATES["containerd"]="containerd.io containerd"
    PKG_CANDIDATES["kubernetes"]="kubectl kubelet kubeadm kubernetes-node"
    PKG_CANDIDATES["k3s"]="k3s"

    # Databases
    PKG_CANDIDATES["mariadb"]="mariadb-server MariaDB-server mariadb"
    PKG_CANDIDATES["mysql"]="mysql-server mysql-community-server"
    PKG_CANDIDATES["postgresql"]="postgresql-server postgresql postgresql16-server postgresql15-server postgresql14-server postgresql13-server"
    PKG_CANDIDATES["mongodb"]="mongodb-org-server mongodb-server"
    PKG_CANDIDATES["redis"]="redis-server redis"
    PKG_CANDIDATES["elasticsearch"]="elasticsearch"
    PKG_CANDIDATES["opensearch"]="opensearch"
    PKG_CANDIDATES["couchbase-server"]="couchbase-server"
    PKG_CANDIDATES["neo4j"]="neo4j"
    PKG_CANDIDATES["influxdb"]="influxdb influxdb2"
    PKG_CANDIDATES["clickhouse"]="clickhouse-server"

    # Message queues
    PKG_CANDIDATES["rabbitmq"]="rabbitmq-server"
    PKG_CANDIDATES["activemq"]="activemq"

    # Web servers & proxies
    PKG_CANDIDATES["nginx"]="nginx nginx-full nginx-light"
    PKG_CANDIDATES["apache-http-server"]="httpd apache2"
    PKG_CANDIDATES["tomcat"]="tomcat tomcat9 tomcat10"
    PKG_CANDIDATES["caddy"]="caddy"
    PKG_CANDIDATES["haproxy"]="haproxy"
    PKG_CANDIDATES["traefik"]="traefik"
    PKG_CANDIDATES["envoy"]="getenvoy-envoy envoy"
    PKG_CANDIDATES["squid"]="squid"
    PKG_CANDIDATES["varnish"]="varnish"

    # Languages & runtimes
    PKG_CANDIDATES["python"]="python3 python39 python310 python311 python312"
    PKG_CANDIDATES["nodejs"]="nodejs"
    PKG_CANDIDATES["php"]="php php-cli php-fpm"
    PKG_CANDIDATES["openjdk"]="java-21-openjdk java-17-openjdk java-11-openjdk java-1.8.0-openjdk"
    PKG_CANDIDATES["go"]="golang go"
    PKG_CANDIDATES["ruby"]="ruby"
    PKG_CANDIDATES["perl"]="perl"
    PKG_CANDIDATES["rust"]="rust rustc"
    PKG_CANDIDATES["dotnet"]="dotnet-runtime-8.0 dotnet-runtime-6.0 aspnetcore-runtime-8.0 dotnet-sdk-8.0"
    PKG_CANDIDATES["lua"]="lua"

    # Security & crypto
    PKG_CANDIDATES["openssl"]="openssl"
    PKG_CANDIDATES["gnutls"]="gnutls gnutls-utils libgnutls30"

    # Monitoring & observability
    PKG_CANDIDATES["grafana"]="grafana"
    PKG_CANDIDATES["prometheus"]="prometheus"
    PKG_CANDIDATES["zabbix"]="zabbix-server zabbix-agent2 zabbix-agent"
    PKG_CANDIDATES["icinga"]="icinga2"
    PKG_CANDIDATES["nagios"]="nagios"
    PKG_CANDIDATES["telegraf"]="telegraf"
    PKG_CANDIDATES["filebeat"]="filebeat"
    PKG_CANDIDATES["logstash"]="logstash"
    PKG_CANDIDATES["kibana"]="kibana"

    # Infrastructure / IaC
    PKG_CANDIDATES["terraform"]="terraform"
    PKG_CANDIDATES["consul"]="consul"
    PKG_CANDIDATES["vault"]="vault"
    PKG_CANDIDATES["nomad"]="nomad"
    PKG_CANDIDATES["packer"]="packer"
    PKG_CANDIDATES["ansible-core"]="ansible-core ansible"
    PKG_CANDIDATES["puppet"]="puppet-agent puppet"
    PKG_CANDIDATES["salt"]="salt-master salt-minion"

    # CI/CD & DevOps
    PKG_CANDIDATES["gitlab"]="gitlab-ce gitlab-ee"
    PKG_CANDIDATES["jenkins"]="jenkins"
    PKG_CANDIDATES["sonarqube"]="sonarqube"
    PKG_CANDIDATES["nexus-repository-manager"]="nexus-repository-manager nexus3"
    PKG_CANDIDATES["harbor"]="harbor"

    # Splunk
    PKG_CANDIDATES["splunk"]="splunk splunkforwarder"

    # Mail
    PKG_CANDIDATES["postfix"]="postfix"
    PKG_CANDIDATES["dovecot"]="dovecot dovecot-core"
    PKG_CANDIDATES["exim"]="exim4 exim"

    # Networking & HA
    PKG_CANDIDATES["keepalived"]="keepalived"
    PKG_CANDIDATES["bird"]="bird bird2"
    PKG_CANDIDATES["wireguard"]="wireguard-tools"
    PKG_CANDIDATES["openvpn"]="openvpn"

    # Storage & caching
    PKG_CANDIDATES["minio"]="minio"
    PKG_CANDIDATES["memcached"]="memcached"
    PKG_CANDIDATES["etcd"]="etcd"
    PKG_CANDIDATES["ceph"]="ceph-common ceph"

    # OS release packages (for detection without /etc/os-release)
    PKG_CANDIDATES["rhel"]="redhat-release redhat-release-server"
    PKG_CANDIDATES["oracle-linux"]="oraclelinux-release oracle-release"
    PKG_CANDIDATES["rocky-linux"]="rocky-release"
    PKG_CANDIDATES["almalinux"]="almalinux-release"
    PKG_CANDIDATES["centos"]="centos-release centos-stream-release"

    # =========================================================================
    # STEP 3: Detect installed products
    # =========================================================================
    local -a eol_products=()
    declare -A detected_products=()   # track what we've found to avoid dupes

    # --- 3a: OS detection (from /etc/os-release — always) ---
    case "$OS_ID" in
        debian)
            eol_products+=("debian:${OS_VERSION%%.*}:Debian:${OS_VERSION}")
            detected_products["debian"]=1 ;;
        ubuntu)
            eol_products+=("ubuntu:${OS_VERSION}:Ubuntu:${OS_VERSION}")
            detected_products["ubuntu"]=1 ;;
        rhel|redhat)
            eol_products+=("rhel:${OS_VERSION%%.*}:RHEL:${OS_VERSION}")
            detected_products["rhel"]=1 ;;
        ol|oracle)
            eol_products+=("oracle-linux:${OS_VERSION%%.*}:Oracle Linux:${OS_VERSION}")
            detected_products["oracle-linux"]=1 ;;
        rocky)
            eol_products+=("rocky-linux:${OS_VERSION%%.*}:Rocky Linux:${OS_VERSION}")
            detected_products["rocky-linux"]=1 ;;
        almalinux|alma)
            eol_products+=("almalinux:${OS_VERSION%%.*}:AlmaLinux:${OS_VERSION}")
            detected_products["almalinux"]=1 ;;
        centos)
            eol_products+=("centos:${OS_VERSION%%.*}:CentOS:${OS_VERSION}")
            detected_products["centos"]=1 ;;
        fedora)
            eol_products+=("fedora:${OS_VERSION}:Fedora:${OS_VERSION}")
            detected_products["fedora"]=1 ;;
        opensuse*|sles)
            eol_products+=("opensuse:${OS_VERSION%%.*}:openSUSE:${OS_VERSION}")
            detected_products["opensuse"]=1 ;;
        alpine)
            local alpine_cycle="${OS_VERSION%.*}"
            eol_products+=("alpine-linux:${alpine_cycle}:Alpine Linux:${OS_VERSION}")
            detected_products["alpine-linux"]=1 ;;
    esac

    # --- 3b: Linux Kernel (always) ---
    local kernel_cycle
    kernel_cycle=$(uname -r | grep -oP '^[0-9]+\.[0-9]+')
    if [[ -n "$kernel_cycle" ]]; then
        eol_products+=("linux:${kernel_cycle}:Linux Kernel:$(uname -r)")
        detected_products["linux"]=1
    fi

    # --- 3c: Proxmox VE (command only, not a standard package) ---
    if command -v pveversion &>/dev/null; then
        local pve_ver
        pve_ver=$(pveversion 2>/dev/null | grep -oP 'pve-manager/\K[0-9]+\.[0-9]+' || true)
        if [[ -n "$pve_ver" ]]; then
            eol_products+=("proxmox-ve:${pve_ver%%.*}:Proxmox VE:${pve_ver}")
            detected_products["proxmox-ve"]=1
        fi
    fi

    # --- 3d: AUTO-MATCH from full dump ---
    if [[ "$use_full_dump" == "true" ]]; then

        # Pre-extract product cycles into a temp lookup file (ONE jq call)
        # Format: product_slug\tcycle_name
        local TMP_CYCLES
        TMP_CYCLES=$(mktemp)
        jq -r '.result[] | .name as $p | .releases[]? | "\($p)\t\(.name)"' \
            "$EOL_FULL_DUMP" > "$TMP_CYCLES" 2>/dev/null

        # Pre-extract product labels (ONE jq call)
        # Format: product_slug\tlabel
        local TMP_LABELS
        TMP_LABELS=$(mktemp)
        jq -r '.result[] | [.name, .label] | @tsv' \
            "$EOL_FULL_DUMP" > "$TMP_LABELS" 2>/dev/null

        # Iterate every product in the dump
        while IFS=$'\t' read -r product_slug product_label; do
            # Skip products already detected (OS, kernel, proxmox)
            [[ -n "${detected_products[$product_slug]+x}" ]] && continue

            # Get candidate package names for this product
            local -a candidates=()
            if [[ -n "${PKG_CANDIDATES[$product_slug]+x}" ]]; then
                IFS=' ' read -ra candidates <<< "${PKG_CANDIDATES[$product_slug]}"
            else
                # Default: try the slug itself and slug-server
                candidates=("$product_slug" "${product_slug}-server")
            fi

            # Check each candidate against installed packages
            local found_ver=""
            for candidate in "${candidates[@]}"; do
                if [[ -n "${INSTALLED_PKGS[$candidate]+x}" ]]; then
                    found_ver="${INSTALLED_PKGS[$candidate]}"
                    break
                fi
            done

            # Not installed — skip
            [[ -z "$found_ver" ]] && continue

            # Clean DEB version strings (strip epoch, revision, build meta)
            if [[ "$PKG_FAMILY" == "deb" ]]; then
                found_ver="${found_ver#*:}"       # strip epoch  (1:3.2.12 → 3.2.12)
                found_ver="${found_ver%%-*}"      # strip revision (-1ubuntu1)
                found_ver="${found_ver%%+*}"      # strip build meta (+dfsg)
                found_ver="${found_ver%%~*}"      # strip tilde suffix
            fi

            # Find matching cycle: try full version, major.minor, then major
            local found_cycle=""
            local ver_major="${found_ver%%.*}"
            local ver_major_minor="${found_ver%.*}"

            # Some products use just major (e.g. PostgreSQL "16", Node "22")
            # Some use major.minor (e.g. Python "3.12", Redis "7.2")
            # Some use full version (e.g. Ubuntu "22.04")
            for try_cycle in "$found_ver" "$ver_major_minor" "$ver_major"; do
                [[ -z "$try_cycle" ]] && continue
                if grep -qP "^\Q${product_slug}\E\t\Q${try_cycle}\E$" "$TMP_CYCLES" 2>/dev/null; then
                    found_cycle="$try_cycle"
                    break
                fi
            done

            # No matching cycle found — skip
            [[ -z "$found_cycle" ]] && continue

            eol_products+=("${product_slug}:${found_cycle}:${product_label}:${found_ver}")
            detected_products["$product_slug"]=1

        done < "$TMP_LABELS"

        # Clean up temp files
        rm -f "$TMP_CYCLES" "$TMP_LABELS"

    else
        # =================================================================
        # LEGACY MODE: hardcoded detection (no full dump available)
        # Uses get_pkg_version with command fallback, same as before.
        # =================================================================

        # Docker Engine
        local docker_ver=""
        docker_ver=$(get_pkg_version "docker-ce" 2>/dev/null || get_pkg_version "docker-engine" 2>/dev/null || true)
        if [[ -z "$docker_ver" ]] && command -v docker &>/dev/null; then
            docker_ver=$(docker version --format '{{.Server.Version}}' 2>/dev/null || true)
        fi
        if [[ -n "$docker_ver" && "$docker_ver" != "unknown" ]]; then
            eol_products+=("docker-engine:${docker_ver%%.*}:Docker Engine:${docker_ver}")
        fi

        # Nginx
        local nginx_ver=""
        nginx_ver=$(get_pkg_version "nginx" 2>/dev/null || get_pkg_version "nginx-full" 2>/dev/null || true)
        if [[ -z "$nginx_ver" ]] && command -v nginx &>/dev/null; then
            nginx_ver=$(nginx -v 2>&1 | grep -oP 'nginx/\K[0-9]+\.[0-9]+\.[0-9]+' || true)
        fi
        if [[ -n "$nginx_ver" ]]; then
            eol_products+=("nginx:${nginx_ver%.*}:Nginx:${nginx_ver}")
        fi

        # PostgreSQL
        local pg_ver=""
        pg_ver=$(get_pkg_version "postgresql-server" 2>/dev/null || get_pkg_version "postgresql" 2>/dev/null || true)
        if [[ -z "$pg_ver" ]]; then
            if command -v psql &>/dev/null; then
                pg_ver=$(psql --version 2>/dev/null | grep -oP '[0-9]+\.[0-9]+' | head -1 || true)
            fi
        fi
        if [[ -n "$pg_ver" ]]; then
            eol_products+=("postgresql:${pg_ver%%.*}:PostgreSQL:${pg_ver}")
        fi

        # Python 3
        local py_ver=""
        py_ver=$(get_pkg_version "python3" 2>/dev/null || true)
        if [[ -z "$py_ver" ]] && command -v python3 &>/dev/null; then
            py_ver=$(python3 --version 2>/dev/null | grep -oP '[0-9]+\.[0-9]+\.[0-9]+' || true)
        fi
        if [[ -n "$py_ver" ]]; then
            eol_products+=("python:${py_ver%.*}:Python:${py_ver}")
        fi

        # Node.js
        local node_ver=""
        node_ver=$(get_pkg_version "nodejs" 2>/dev/null || true)
        if [[ -z "$node_ver" ]] && command -v node &>/dev/null; then
            node_ver=$(node --version 2>/dev/null | grep -oP '[0-9]+\.[0-9]+\.[0-9]+' || true)
        fi
        if [[ -n "$node_ver" ]]; then
            eol_products+=("nodejs:${node_ver%%.*}:Node.js:${node_ver}")
        fi

        # OpenSSL
        local ssl_ver=""
        ssl_ver=$(get_pkg_version "openssl" 2>/dev/null || true)
        if [[ -z "$ssl_ver" ]] && command -v openssl &>/dev/null; then
            ssl_ver=$(openssl version 2>/dev/null | grep -oP '[0-9]+\.[0-9]+\.[0-9]+' || true)
        fi
        if [[ -n "$ssl_ver" ]]; then
            eol_products+=("openssl:${ssl_ver%.*}:OpenSSL:${ssl_ver}")
        fi

        # Grafana
        local graf_ver=""
        graf_ver=$(get_pkg_version "grafana" 2>/dev/null || true)
        if [[ -z "$graf_ver" ]] && command -v grafana-server &>/dev/null; then
            graf_ver=$(grafana-server -v 2>/dev/null | grep -oP '[0-9]+\.[0-9]+\.[0-9]+' || true)
        fi
        if [[ -n "$graf_ver" ]]; then
            eol_products+=("grafana:${graf_ver%.*}:Grafana:${graf_ver}")
        fi
    fi

    # =========================================================================
    # STEP 4: Load custom overrides from eol-products.conf
    # =========================================================================
    # In auto-match mode:  overrides replace auto-detected entries
    # In legacy mode:      additions to the hardcoded list
    if [[ -f "$CUSTOM_EOL_FILE" ]]; then
        while IFS= read -r line; do
            line="${line%%#*}"
            line=$(echo "$line" | xargs 2>/dev/null || echo "$line")
            [[ -z "$line" ]] && continue

            local field_count
            field_count=$(echo "$line" | awk -F: '{print NF}')
            if [[ "$field_count" -ge 3 ]]; then
                local override_product="${line%%:*}"

                # Remove any auto-detected entry for this product (override wins)
                local -a new_products=()
                for existing in "${eol_products[@]}"; do
                    local existing_product="${existing%%:*}"
                    [[ "$existing_product" != "$override_product" ]] && new_products+=("$existing")
                done
                eol_products=("${new_products[@]}")

                # Add the override
                eol_products+=("$line")
                detected_products["$override_product"]=1
            fi
        done < "$CUSTOM_EOL_FILE"
    fi

    # --- Nothing to check? ---
    if [[ ${#eol_products[@]} -eq 0 ]]; then
        return 0
    fi

    # =========================================================================
    # STEP 5: Process detected products → Prometheus metrics
    # =========================================================================

    # Write metric headers
    {
        echo ""
        echo "# HELP linux_eol_product_info End-of-life information per detected product. Value is always 1."
        echo "# TYPE linux_eol_product_info gauge"
        echo ""
        echo "# HELP linux_eol_days_remaining Days until end-of-life. Negative means already EOL."
        echo "# TYPE linux_eol_days_remaining gauge"
        echo ""
        echo "# HELP linux_eol_is_eol Whether this product cycle has reached end-of-life. 1=EOL, 0=supported."
        echo "# TYPE linux_eol_is_eol gauge"
        echo ""
        echo "# HELP linux_eol_supported_until Unix timestamp of the EOL date (0 if boolean/unknown)."
        echo "# TYPE linux_eol_supported_until gauge"
    } >> "$TMP_EOL_FILE"

    local today_epoch
    today_epoch=$(date +%s)

    local eol_count=0
    local eol_ok=0
    local eol_expired=0

    for entry in "${eol_products[@]}"; do
        IFS=':' read -r product cycle label installed_ver <<< "$entry"
        [[ -z "$installed_ver" ]] && installed_ver="$cycle"

        local eol_val=""
        local latest_ver=""

        if [[ "$use_full_dump" == "true" ]]; then
            # ---- v1 full dump lookup ----
            local release_data
            release_data=$(jq -r --arg p "$product" --arg c "$cycle" '
                [.result[]? | select(.name == $p) |
                .releases[]? | select(
                    (.name | tostring) == $c or
                    (.name | tostring | startswith($c + "."))
                )] | first // empty
            ' "$EOL_FULL_DUMP" 2>/dev/null || true)

            if [[ -n "$release_data" && "$release_data" != "null" ]]; then
                local is_eol_bool
                is_eol_bool=$(echo "$release_data" | jq -r '.isEol // false')
                eol_val=$(echo "$release_data" | jq -r '.eolFrom // "unknown"')
                latest_ver=$(echo "$release_data" | jq -r '.latest.name // .latest // "unknown"')

                if [[ "$is_eol_bool" == "true" && ("$eol_val" == "unknown" || "$eol_val" == "null") ]]; then
                    eol_val="true"
                fi
            else
                echo "linux_eol_product_info{product=\"$(prom_escape "$label")\",cycle=\"$(prom_escape "$cycle")\",installed=\"$(prom_escape "$installed_ver")\",eol_date=\"not_tracked\",latest=\"unknown\",status=\"no_match\"} 1" >> "$TMP_EOL_FILE"
                continue
            fi
        else
            # ---- Per-product cache / live API fallback ----
            local cache_file="${EOL_CACHE_DIR}/${product}.json"
            local use_cache=false

            if [[ -f "$cache_file" ]]; then
                local cache_age=$(( today_epoch - $(stat -c %Y "$cache_file" 2>/dev/null || echo 0) ))
                if [[ $cache_age -lt $EOL_CACHE_MAX_AGE ]]; then
                    use_cache=true
                fi
            fi

            if [[ "$use_cache" != "true" ]]; then
                if command -v curl &>/dev/null; then
                    if ! curl_with_retry "${EOL_API_LEGACY}/${product}.json" "$cache_file"; then
                        if [[ ! -f "$cache_file" ]]; then
                            echo "linux_eol_product_info{product=\"$(prom_escape "$label")\",cycle=\"$(prom_escape "$cycle")\",installed=\"$(prom_escape "$installed_ver")\",eol_date=\"unknown\",latest=\"unknown\",status=\"fetch_failed\"} 1" >> "$TMP_EOL_FILE"
                            continue
                        fi
                    fi
                elif [[ ! -f "$cache_file" ]]; then
                    echo "linux_eol_product_info{product=\"$(prom_escape "$label")\",cycle=\"$(prom_escape "$cycle")\",installed=\"$(prom_escape "$installed_ver")\",eol_date=\"unknown\",latest=\"unknown\",status=\"no_data\"} 1" >> "$TMP_EOL_FILE"
                    continue
                fi
            fi

            local cycle_data
            cycle_data=$(jq -r --arg c "$cycle" '
                [.[] | select(
                    (.cycle | tostring) == $c or
                    (.cycle | tostring | startswith($c + "."))
                )] | first // empty
            ' "$cache_file" 2>/dev/null || true)

            if [[ -z "$cycle_data" || "$cycle_data" == "null" ]]; then
                echo "linux_eol_product_info{product=\"$(prom_escape "$label")\",cycle=\"$(prom_escape "$cycle")\",installed=\"$(prom_escape "$installed_ver")\",eol_date=\"not_tracked\",latest=\"unknown\",status=\"no_match\"} 1" >> "$TMP_EOL_FILE"
                continue
            fi

            eol_val=$(echo "$cycle_data" | jq -r '.eol // "unknown"')
            latest_ver=$(echo "$cycle_data" | jq -r '.latest // "unknown"')
        fi

        # ---- Common: determine status and days remaining ----
        local is_eol=0
        local days_remaining=9999
        local eol_epoch=0
        local status="supported"

        if [[ "$eol_val" == "true" ]]; then
            is_eol=1
            days_remaining=-1
            status="eol"
        elif [[ "$eol_val" == "false" ]]; then
            is_eol=0
            days_remaining=9999
            status="supported"
        elif [[ "$eol_val" =~ ^[0-9]{4}-[0-9]{2}-[0-9]{2}$ ]]; then
            eol_epoch=$(date -d "$eol_val" +%s 2>/dev/null || echo 0)
            if [[ $eol_epoch -gt 0 ]]; then
                days_remaining=$(( (eol_epoch - today_epoch) / 86400 ))
                if [[ $days_remaining -lt 0 ]]; then
                    is_eol=1
                    status="eol"
                elif [[ $days_remaining -lt 90 ]]; then
                    status="warning"
                elif [[ $days_remaining -lt 180 ]]; then
                    status="attention"
                fi
            fi
        fi

        # Write metrics
        {
            echo "linux_eol_product_info{product=\"$(prom_escape "$label")\",cycle=\"$(prom_escape "$cycle")\",installed=\"$(prom_escape "$installed_ver")\",eol_date=\"$(prom_escape "$eol_val")\",latest=\"$(prom_escape "$latest_ver")\",status=\"$status\"} 1"
            echo "linux_eol_days_remaining{product=\"$(prom_escape "$label")\",cycle=\"$(prom_escape "$cycle")\"} $days_remaining"
            echo "linux_eol_is_eol{product=\"$(prom_escape "$label")\",cycle=\"$(prom_escape "$cycle")\"} $is_eol"
            echo "linux_eol_supported_until{product=\"$(prom_escape "$label")\",cycle=\"$(prom_escape "$cycle")\"} $eol_epoch"
        } >> "$TMP_EOL_FILE"

        eol_count=$((eol_count + 1))
        if [[ $is_eol -eq 1 ]]; then
            eol_expired=$((eol_expired + 1))
        else
            eol_ok=$((eol_ok + 1))
        fi
    done

    # Summary metrics
    {
        echo ""
        echo "# HELP linux_eol_products_checked Total number of products checked against endoflife.date."
        echo "# TYPE linux_eol_products_checked gauge"
        echo "linux_eol_products_checked $eol_count"
        echo ""
        echo "# HELP linux_eol_products_ok Number of products still within support."
        echo "# TYPE linux_eol_products_ok gauge"
        echo "linux_eol_products_ok $eol_ok"
        echo ""
        echo "# HELP linux_eol_products_expired Number of products that have reached end-of-life."
        echo "# TYPE linux_eol_products_expired gauge"
        echo "linux_eol_products_expired $eol_expired"
        echo ""
        echo "# HELP linux_eol_data_source How EOL data was loaded. 1=full_dump, 2=per_product_cache."
        echo "# TYPE linux_eol_data_source gauge"
        if [[ "$use_full_dump" == "true" ]]; then
            echo "linux_eol_data_source{source=\"full_dump\",file=\"eol-full.json\"} 1"
        else
            echo "linux_eol_data_source{source=\"per_product_cache\",file=\"eol-cache/\"} 2"
        fi
    } >> "$TMP_EOL_FILE"
}

# --- Run EOL check in PARALLEL (runs in background while main output finalises) ---
check_eol &
eol_pid=$!

# --- Wait for the parallel EOL check to finish, then merge its output ---
wait "$eol_pid" 2>/dev/null || true
if [[ -s "$TMP_EOL_FILE" ]]; then
    cat "$TMP_EOL_FILE" >> "$TMP_OUTPUT_FILE"
fi

# --- Final total duration (including EOL) ---
{
    echo ""
    echo "# HELP linux_inventory_script_duration_total_seconds Total wall-clock time including parallel EOL checks."
    echo "# TYPE linux_inventory_script_duration_total_seconds gauge"
    echo "linux_inventory_script_duration_total_seconds $SECONDS"
} >> "$TMP_OUTPUT_FILE"

# --- Atomically move to final destination ---
mv "$TMP_OUTPUT_FILE" "$OUTPUT_FILE"
trap - EXIT

echo "Linux inventory generated: $package_count packages, $updates_total updates ($security_total security), written to $OUTPUT_FILE (${SECONDS}s)"
INVENTORY_SCRIPT_EOF

chmod 755 "${INSTALL_DIR}/linux_inventory.sh"
log "Deployed linux_inventory.sh ($(wc -l < "${INSTALL_DIR}/linux_inventory.sh") lines)"

# =================================================================
# STEP 4: Deploy eol-products.conf (only if not already present)
# =================================================================
if [[ -f "${INSTALL_DIR}/eol-products.conf" ]]; then
    warn "eol-products.conf already exists — preserving your customisations"
else
    info "Deploying eol-products.conf..."

    cat > "${INSTALL_DIR}/eol-products.conf" << 'EOL_CONFIG_EOF'
# =============================================================================
# EOL Product Overrides — /data/software/.../eol-products.conf
# =============================================================================
#
# *** YOU PROBABLY DON'T NEED TO ADD ANYTHING HERE ***
#
# When eol-full.json is present (pushed by Ansible), the script AUTO-MATCHES
# every installed package against all 430+ products in endoflife.date.
# Docker, PostgreSQL, Nginx, Redis, RabbitMQ, etc. are found automatically.
#
# This file is for:
#   1. OVERRIDES  — fix a wrong auto-detected version or cycle
#   2. ADDITIONS  — software that isn't in a package (containers, binaries, etc.)
#
# Format (one per line):
#   product:cycle:label:version
#
# Fields:
#   product  — endoflife.date product slug (required)
#   cycle    — release cycle to check (required)
#   label    — display name for Grafana dashboards (required)
#   version  — installed version (optional, defaults to cycle)
#
# Lines starting with # are comments. Blank lines are ignored.
#
# How to find the product slug:
#   curl -s https://endoflife.date/api/all.json | jq -r '.[]' | grep -i <name>
#
# =============================================================================

# --- Overrides (uncomment if auto-detection gets it wrong) ---
# Example: Splunk Forwarder detected as wrong cycle
# splunk:9.4:Splunk Forwarder:9.4.7

# --- Additions (software not installed as a system package) ---
# Example: Kubernetes running in containers, not as a host package
# kubernetes:1.29:Kubernetes:1.29.3

# Example: Terraform is a single binary, not a package
# terraform:1.7:Terraform:1.7.5
EOL_CONFIG_EOF

    chmod 644 "${INSTALL_DIR}/eol-products.conf"
    log "Deployed eol-products.conf"
fi

# =================================================================
# STEP 5: Fetch full EOL dump from endoflife.date API
# =================================================================
if [[ "$DO_FETCH" == "true" ]]; then
    info "Fetching EOL data from endoflife.date API (this may take a moment)..."

    if command -v curl &>/dev/null; then
        HTTP_CODE=$(curl -sf --max-time 60 \
            -H "Accept: application/json" \
            -w "%{http_code}" \
            -o "${INSTALL_DIR}/eol-full.json" \
            "$EOL_API_URL" 2>/dev/null) || HTTP_CODE="000"

        if [[ "$HTTP_CODE" == "200" ]]; then
            DUMP_SIZE=$(du -h "${INSTALL_DIR}/eol-full.json" | cut -f1)
            PRODUCT_COUNT=$(jq -r '.total // .result | length' "${INSTALL_DIR}/eol-full.json" 2>/dev/null || echo "?")
            log "Downloaded eol-full.json (${DUMP_SIZE}, ${PRODUCT_COUNT} products)"
        else
            err "Failed to fetch EOL dump (HTTP ${HTTP_CODE})."
            warn "The script will still work but EOL checking will use legacy fallback."
            warn "You can retry later: curl -sf '$EOL_API_URL' -o '${INSTALL_DIR}/eol-full.json'"
            rm -f "${INSTALL_DIR}/eol-full.json"
        fi
    else
        warn "curl not installed — skipping EOL fetch."
        warn "Install curl and re-run, or copy eol-full.json from another machine."
    fi
else
    warn "Skipping EOL API fetch (--no-fetch)."
    if [[ -f "${INSTALL_DIR}/eol-full.json" ]]; then
        info "Existing eol-full.json found — will use that."
    else
        warn "No eol-full.json present. Copy one from another machine or re-run without --no-fetch."
    fi
fi

# =================================================================
# STEP 6: Set up cron job
# =================================================================
if [[ "$DO_CRON" == "true" ]]; then
    info "Setting up cron job..."

    CRON_JOB="${CRON_SCHEDULE} ${INSTALL_DIR}/linux_inventory.sh > /dev/null 2>&1"
    CRON_COMMENT="# Linux software inventory collection"

    # Remove old entry if present, then add new one
    (crontab -l 2>/dev/null | grep -v "linux_inventory.sh" ; echo "$CRON_COMMENT" ; echo "$CRON_JOB") | crontab -

    log "Cron job created: ${CRON_SCHEDULE}"
else
    warn "Skipping cron setup (--no-cron)."
fi

# =================================================================
# STEP 7: Run initial collection
# =================================================================
if [[ "$DO_RUN" == "true" ]]; then
    info "Running initial inventory collection..."
    echo ""

    if OUTPUT=$("${INSTALL_DIR}/linux_inventory.sh" 2>&1); then
        log "$OUTPUT"
    else
        err "Initial run failed:"
        echo "$OUTPUT"
        warn "Check the script manually: ${INSTALL_DIR}/linux_inventory.sh"
    fi
else
    warn "Skipping initial run (--no-run)."
fi

# =================================================================
# DONE
# =================================================================
echo ""
echo "=============================================="
echo "  Installation Complete"
echo "=============================================="
echo ""
echo "  Install directory:  ${INSTALL_DIR}"
echo "  Script:             ${INSTALL_DIR}/linux_inventory.sh"
echo "  EOL config:         ${INSTALL_DIR}/eol-products.conf"
echo "  EOL data:           ${INSTALL_DIR}/eol-full.json"
echo "  Metrics output:     ${TEXTFILE_DIR}/linux_inventory.prom"
echo "  Cron schedule:      ${CRON_SCHEDULE}"
echo ""
echo "  To re-run manually: ${INSTALL_DIR}/linux_inventory.sh"
echo "  To uninstall:       $0 --uninstall"
echo ""
