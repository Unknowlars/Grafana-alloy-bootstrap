#!/usr/bin/env bash
# post-install.sh — runs automatically when this pack is selected by setup.sh
# Deploys the linux_inventory.sh script and creates the cron job.
set -euo pipefail

SCRIPT_SRC="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)/linux_inventory.sh"
SCRIPT_DST="/usr/local/bin/linux_inventory.sh"
CRON_FILE="/etc/cron.d/linux-inventory"
TEXTFILE_DIR="/var/lib/prometheus/node-exporter"

echo "  [software-inventory] Deploying inventory script..."

# Install the script
install -m 0755 "$SCRIPT_SRC" "$SCRIPT_DST"
echo "  [software-inventory] Installed $SCRIPT_DST"

# Create the textfile collector directory
mkdir -p "$TEXTFILE_DIR"
chmod 755 "$TEXTFILE_DIR"

# Create cron job (every 6 hours)
cat > "$CRON_FILE" <<'EOF'
# Linux software & system inventory for Prometheus
# Managed by alloy-bootstrap (software-inventory pack)
SHELL=/bin/bash
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
0 */6 * * * root /usr/local/bin/linux_inventory.sh >/dev/null 2>&1
EOF
chmod 644 "$CRON_FILE"
echo "  [software-inventory] Created cron job: $CRON_FILE (runs every 6 hours)"

# Run it once now to generate the initial .prom file
echo "  [software-inventory] Running initial inventory collection..."
if "$SCRIPT_DST"; then
    echo "  [software-inventory] Initial inventory generated successfully."
else
    echo "  [software-inventory] WARNING: Initial inventory run failed (will retry via cron)."
fi
