#!/bin/bash
# =============================================================================
# Linux Software Inventory & System Info — Prometheus Metrics Generator
# =============================================================================
# Generates rich package metadata and system information in Prometheus
# textfile collector format for ingestion via node_exporter or Grafana Alloy.
#
# Supported distros:
#   RPM-based:    RHEL, Oracle Linux, CentOS, Rocky, AlmaLinux, Fedora, SUSE
#   DEB-based:    Ubuntu, Debian, Linux Mint, Pop!_OS
#
# Usage:
#   chmod +x linux_inventory.sh
#   ./linux_inventory.sh
#
# Cron (every 6 hours):
#   0 */6 * * * /usr/local/bin/linux_inventory.sh
#
# Prerequisites:
#   - node_exporter with --collector.textfile.directory or
#     Grafana Alloy with textfile block configured
# =============================================================================

set -euo pipefail

# --- Configuration ---
TEXTFILE_COLLECTOR_DIR="/var/lib/prometheus/node-exporter"
OUTPUT_FILE="$TEXTFILE_COLLECTOR_DIR/linux_inventory.prom"

# --- Setup ---
mkdir -p "$TEXTFILE_COLLECTOR_DIR"
TMP_OUTPUT_FILE=$(mktemp)
chmod 644 "$TMP_OUTPUT_FILE"
trap 'rm -f "$TMP_OUTPUT_FILE"' EXIT

# --- Helper: escape Prometheus label values ---
prom_escape() {
    local val="$1"
    val="${val//\\/\\\\}"
    val="${val//\"/\\\"}"
    val="${val//$'\n'/\\n}"
    printf '%s' "$val"
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

# --- Safe wrapper for commands that return non-zero on success ---
# dnf check-update returns 100 when updates are available
safe_run() {
    "$@" 2>/dev/null || true
}

# =====================================================================
# SECTION 1: System Information
# =====================================================================

KERNEL_VERSION=$(uname -r)
KERNEL_ARCH=$(uname -m)
HOSTNAME_FULL=$(hostname -f 2>/dev/null || hostname)
HOSTNAME_SHORT=$(hostname -s 2>/dev/null || hostname)

# Uptime & last boot
BOOT_TIME=$(cat /proc/stat 2>/dev/null | awk '/^btime/ {print $2}')
if [ -z "$BOOT_TIME" ]; then
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
# SECTION 2: Installed Packages
# =====================================================================

{
    echo ""
    echo "# HELP linux_installed_package Information about an installed package. Value is always 1."
    echo "# TYPE linux_installed_package gauge"
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
    # RPM-based: query rpm + dnf repoquery for repo info
    # ---------------------------------------------------------------

    # Build repo lookup map
    declare -A REPO_MAP
    if [[ "$PKG_MGR" == "dnf" ]]; then
        while IFS=$'\t' read -r nevra repo; do
            [[ -n "$nevra" ]] && REPO_MAP["$nevra"]="$repo"
        done < <(dnf repoquery --installed --qf '%{name}-%{version}-%{release}.%{arch}\t%{from_repo}' 2>/dev/null)
    fi

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

        echo "linux_installed_package{package=\"$e_name\",version=\"$e_version\",arch=\"$e_arch\",repo=\"$e_repo\",vendor=\"$e_vendor\",group=\"$e_group\",summary=\"$e_summary\",install_epoch=\"$installtime\"} 1"

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
    # DEB-based: query dpkg-query for package info
    # ---------------------------------------------------------------

    # Build origin/repo lookup from apt-cache policy (best effort)
    declare -A DEB_REPO_MAP
    while IFS=$'\t' read -r pkg origin; do
        [[ -n "$pkg" ]] && DEB_REPO_MAP["$pkg"]="$origin"
    done < <(apt-cache policy $(dpkg-query -W -f='${Package}\n' 2>/dev/null) 2>/dev/null | awk '
        /^[a-zA-Z0-9]/ { pkg=$1; sub(/:$/,"",pkg) }
        /\*\*\*/ { getline; if ($0 ~ /http/ || $0 ~ /\//) { origin=$2; sub(/^.*\/\//,"",origin); sub(/\/.*/,"",origin); print pkg "\t" origin } }
    ' 2>/dev/null || true)

    # dpkg-query format:
    # Package\tVersion\tArchitecture\tInstalled-Size(KB)\tSection\tMaintainer\tDescription(oneline)
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

        echo "linux_installed_package{package=\"$e_name\",version=\"$e_version\",arch=\"$e_arch\",repo=\"$e_repo\",vendor=\"$e_vendor\",group=\"$e_group\",summary=\"$e_summary\",install_epoch=\"$installtime\"} 1"

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
# SECTION 3: Package Install Times (dedicated metric for time queries)
# =====================================================================
{
    echo ""
    echo "# HELP linux_package_install_time_seconds Unix timestamp when the package was installed."
    echo "# TYPE linux_package_install_time_seconds gauge"
} >> "$TMP_OUTPUT_FILE"

if [[ "$PKG_FAMILY" == "rpm" ]]; then
    while IFS=$'\t' read -r name version arch installtime; do
        [[ -z "$name" || -z "$installtime" || "$installtime" == "0" ]] && continue
        e_name=$(prom_escape "$name")
        e_version=$(prom_escape "$version")
        e_arch=$(prom_escape "$arch")
        echo "linux_package_install_time_seconds{package=\"$e_name\",version=\"$e_version\",arch=\"$e_arch\"} $installtime"
    done < <(rpm -qa --qf '%{NAME}\t%{VERSION}-%{RELEASE}\t%{ARCH}\t%{INSTALLTIME}\n') >> "$TMP_OUTPUT_FILE"

elif [[ "$PKG_FAMILY" == "deb" ]]; then
    while IFS=$'\t' read -r name version arch; do
        [[ -z "$name" ]] && continue
        installtime="0"
        for listfile in "/var/lib/dpkg/info/${name}.list" "/var/lib/dpkg/info/${name}:${arch}.list"; do
            if [ -f "$listfile" ]; then
                installtime=$(stat -c %Y "$listfile" 2>/dev/null || echo "0")
                break
            fi
        done
        [[ "$installtime" == "0" ]] && continue
        e_name=$(prom_escape "$name")
        e_version=$(prom_escape "$version")
        e_arch=$(prom_escape "$arch")
        echo "linux_package_install_time_seconds{package=\"$e_name\",version=\"$e_version\",arch=\"$e_arch\"} $installtime"
    done < <(dpkg-query -W -f='${Package}\t${Version}\t${Architecture}\n' 2>/dev/null) >> "$TMP_OUTPUT_FILE"
fi


# =====================================================================
# SECTION 4: Package Sizes (dedicated metric for size queries)
# =====================================================================
{
    echo ""
    echo "# HELP linux_package_size_bytes Installed size of the package in bytes."
    echo "# TYPE linux_package_size_bytes gauge"
} >> "$TMP_OUTPUT_FILE"

if [[ "$PKG_FAMILY" == "rpm" ]]; then
    while IFS=$'\t' read -r name version arch size; do
        [[ -z "$name" ]] && continue
        e_name=$(prom_escape "$name")
        e_version=$(prom_escape "$version")
        e_arch=$(prom_escape "$arch")
        echo "linux_package_size_bytes{package=\"$e_name\",version=\"$e_version\",arch=\"$e_arch\"} $size"
    done < <(rpm -qa --qf '%{NAME}\t%{VERSION}-%{RELEASE}\t%{ARCH}\t%{SIZE}\n') >> "$TMP_OUTPUT_FILE"

elif [[ "$PKG_FAMILY" == "deb" ]]; then
    while IFS=$'\t' read -r name version arch size_kb; do
        [[ -z "$name" ]] && continue
        size=$((size_kb * 1024))
        e_name=$(prom_escape "$name")
        e_version=$(prom_escape "$version")
        e_arch=$(prom_escape "$arch")
        echo "linux_package_size_bytes{package=\"$e_name\",version=\"$e_version\",arch=\"$e_arch\"} $size"
    done < <(dpkg-query -W -f='${Package}\t${Version}\t${Architecture}\t${Installed-Size}\n' 2>/dev/null) >> "$TMP_OUTPUT_FILE"
fi


# =====================================================================
# SECTION 5: Available Updates
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
# SECTION 6: Listening Services / Open Ports
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
# SECTION 7: Docker / Container Info (if available)
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
# SECTION 8: Summary / Aggregate Metrics
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
    echo "# HELP linux_inventory_script_duration_seconds How long the inventory script took to run."
    echo "# TYPE linux_inventory_script_duration_seconds gauge"
    echo "linux_inventory_script_duration_seconds $SECONDS"

} >> "$TMP_OUTPUT_FILE"

# --- Atomically move to final destination ---
mv "$TMP_OUTPUT_FILE" "$OUTPUT_FILE"
trap - EXIT

echo "Linux inventory generated: $package_count packages, $updates_total updates ($security_total security), written to $OUTPUT_FILE (${SECONDS}s)"
