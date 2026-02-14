# Linux Software Inventory & EOL Tracker

A comprehensive Prometheus-based solution for Linux fleet inventory management, software lifecycle tracking, and compliance monitoring. Generates rich package metadata, system information, and end-of-life status in Prometheus textfile collector format for ingestion via node_exporter or Grafana Alloy.

![Grafana Dashboard](https://img.shields.io/badge/Grafana-Dashboard_Included-orange?logo=grafana)
![Shell](https://img.shields.io/badge/Shell-Bash_4%2B-green?logo=gnubash)

## Screenshots

<div align="center">
  <img src="https://raw.githubusercontent.com/Unknowlars/Grafana-alloy-bootstrap/main/alloy-bootstrap/templates/packs/80-software-inventory/screenshots/Summary.png" alt="Software Inventory Summary" width="90%" />
  <p><em>Software inventory summary with key risk and compliance indicators</em></p>
</div>

<div align="center">
  <img src="https://raw.githubusercontent.com/Unknowlars/Grafana-alloy-bootstrap/main/alloy-bootstrap/templates/packs/80-software-inventory/screenshots/End_of_life_tracking.png" alt="Fleet Overview, Security and Certificates" width="90%" />
  <p><em>End of Life Tracking</em></p>
</div>

<details>
<summary><strong>📸 View All Screenshots</strong></summary>

### Fleet & Security
| | |
|:---:|:---:|
| ![Summary](https://raw.githubusercontent.com/Unknowlars/Grafana-alloy-bootstrap/main/alloy-bootstrap/templates/packs/80-software-inventory/screenshots/Summary.png) | ![Fleet Overview, Security and Certificates](https://raw.githubusercontent.com/Unknowlars/Grafana-alloy-bootstrap/main/alloy-bootstrap/templates/packs/80-software-inventory/screenshots/fleet_overview_and_security_and_certs.png) |
| Summary | Fleet Overview, Security & Certificates |

### Software Lifecycle
| | |
|:---:|:---:|
| ![End of Life Tracking](https://raw.githubusercontent.com/Unknowlars/Grafana-alloy-bootstrap/main/alloy-bootstrap/templates/packs/80-software-inventory/screenshots/End_of_life_tracking.png) | ![Package Management 1](https://raw.githubusercontent.com/Unknowlars/Grafana-alloy-bootstrap/main/alloy-bootstrap/templates/packs/80-software-inventory/screenshots/Package_mangement_1.png) |
| End-of-Life Tracking | Package Management Overview |
| ![Package Management 2](https://raw.githubusercontent.com/Unknowlars/Grafana-alloy-bootstrap/main/alloy-bootstrap/templates/packs/80-software-inventory/screenshots/Package_mangement_2.png) | ![Docker, Containers, and Network Listening Ports](https://raw.githubusercontent.com/Unknowlars/Grafana-alloy-bootstrap/main/alloy-bootstrap/templates/packs/80-software-inventory/screenshots/docker_and_containers_and_network_listening_ports.png) |
| Package Management Details | Docker, Containers & Listening Ports |

</details>


## Features

### 📦 Package Inventory
- Complete package enumeration with version, architecture, vendor, and repository information
- Install timestamps and package sizes
- Aggregation by repository, vendor, architecture, and package group
- Available updates detection (including security-specific updates)

### ⏳ End-of-Life Tracking
- **Auto-discovery mode**: Automatically matches 430+ products from [endoflife.date](https://endoflife.date) against installed packages
- Support status with days remaining until EOL
- Configurable product overrides via `eol-products.conf`
- Tracks OS distributions, kernels, databases, web servers, languages, and more

### 🖥️ System Information
- OS details (distribution, version, kernel, architecture)
- Hardware specs (CPU model, cores, sockets, memory, disk)
- Virtualization detection (bare-metal, VM, container)
- Security framework status (SELinux/AppArmor)
- Firewall state and NTP synchronization

### 🔒 Security Metrics
- SSL/TLS certificate expiry monitoring
- SUID/SGID file counts
- Journal error tracking (24-hour window)
- Reboot requirement detection
- Failed systemd service count

### 🐳 Docker Integration
- Container counts (running/stopped)
- Image inventory
- Docker engine version

### 🌐 Network Visibility
- Listening port enumeration
- Process-to-port mapping

## Supported Distributions

| Family | Distributions |
|--------|---------------|
| **RPM-based** | RHEL, Oracle Linux, CentOS, Rocky Linux, AlmaLinux, Fedora, openSUSE |
| **DEB-based** | Ubuntu, Debian, Linux Mint, Pop!_OS, Proxmox VE |

## Quick Start

### Option 1: One-Line Installer

```bash
curl -sL https://raw.githubusercontent.com/Unknowlars/Grafana-alloy-bootstrap/refs/heads/main/alloy-bootstrap/templates/packs/80-software-inventory/deploy-inventory.sh | sudo bash
```

### Option 2: Manual Installation

```bash
# Clone or download the repository
git clone https://github.com/Unknowlars/Grafana-alloy-bootstrap.git
cd alloy-bootstrap/templates/packs/80-software-inventory

# Deploy the script
sudo install -m 0755 linux_inventory.sh /usr/local/bin/

# Create directories
sudo mkdir -p /var/lib/prometheus/node-exporter

# Run initial collection
sudo /usr/local/bin/linux_inventory.sh

# Set up cron (every 6 hours)
echo "0 */6 * * * root /usr/local/bin/linux_inventory.sh >/dev/null 2>&1" | sudo tee /etc/cron.d/linux-inventory
```

### Option 3: Alloy Bootstrap Integration

If you're using the alloy-bootstrap, the pack is automatically deployed when selected during `setup.sh`:

```bash
./setup.sh
# Select "software-inventory" pack when prompted
```

## Configuration

### Directory Structure

```
/data/software/application_scripts/software_inventory/
├── linux_inventory.sh      # Main collection script
├── eol-products.conf       # Custom EOL product overrides (optional)
├── eol-full.json           # Full endoflife.date API dump (auto-fetched)
└── eol-cache/              # Per-product cache fallback directory
```

### Output Location

Metrics are written to:
```
/var/lib/prometheus/node-exporter/linux_inventory.prom
```

### EOL Auto-Discovery

When `eol-full.json` is present (fetched automatically by the installer), the script:

1. Loads the complete product database from endoflife.date (~430 products)
2. Scans all installed packages
3. Automatically matches packages to EOL products using intelligent mapping
4. No manual configuration required—install RabbitMQ tomorrow, and it's tracked automatically

### Custom EOL Overrides

Create `eol-products.conf` in the script directory to:
- Override auto-detected product versions
- Add products not matched by auto-discovery
- Exclude false-positive matches

Format: `product:cycle:label:version`

```conf
# Example: Override detected MySQL version
mysql:8.0:MySQL:8.0.35

# Example: Add custom product
custom-app:2.5:Custom Application:2.5.1
```

### Package-to-Product Mapping

The script includes intelligent mapping for 100+ products where package names differ from endoflife.date slugs:

| Product | Package Candidates |
|---------|-------------------|
| `docker-engine` | docker-ce, docker-engine, docker.io |
| `postgresql` | postgresql-server, postgresql, postgresql16-server |
| `nginx` | nginx, nginx-full, nginx-light |
| `openjdk` | java-21-openjdk, java-17-openjdk, java-11-openjdk |

## Metrics Reference

### System Information

| Metric | Type | Description |
|--------|------|-------------|
| `linux_system_info` | gauge | System labels (OS, kernel, hostname, virtualization) |
| `linux_cpu_info` | gauge | CPU model, cores, sockets, threads |
| `linux_boot_time_seconds` | gauge | Unix timestamp of last boot |
| `linux_uptime_seconds` | gauge | System uptime |
| `linux_memory_total_bytes` | gauge | Total physical memory |
| `linux_swap_total_bytes` | gauge | Total swap space |
| `linux_rootfs_*_bytes` | gauge | Root filesystem size/used/available |

### Package Inventory

| Metric | Type | Description |
|--------|------|-------------|
| `linux_installed_package` | gauge | Package info (name, version, arch, repo, vendor) |
| `linux_package_install_time_seconds` | gauge | Package installation timestamp |
| `linux_package_size_bytes` | gauge | Installed package size |
| `linux_inventory_packages_total` | gauge | Total installed packages |
| `linux_inventory_size_bytes_total` | gauge | Total size of all packages |
| `linux_inventory_packages_by_repo` | gauge | Package count per repository |
| `linux_inventory_packages_by_vendor` | gauge | Package count per vendor |

### Updates

| Metric | Type | Description |
|--------|------|-------------|
| `linux_package_update_available` | gauge | Available package update |
| `linux_package_update_security` | gauge | Security update pending |
| `linux_inventory_updates_available_total` | gauge | Total pending updates |
| `linux_inventory_security_updates_total` | gauge | Total security updates |

### End-of-Life

| Metric | Type | Description |
|--------|------|-------------|
| `linux_eol_product_info` | gauge | EOL product details (cycle, installed version, EOL date, latest version, status) |
| `linux_eol_days_remaining` | gauge | Days until EOL (negative = already EOL) |
| `linux_eol_is_eol` | gauge | Whether product is EOL (1=EOL, 0=supported) |
| `linux_eol_supported_until` | gauge | Unix timestamp of EOL date |
| `linux_eol_products_checked` | gauge | Total products checked |
| `linux_eol_products_ok` | gauge | Products still supported |
| `linux_eol_products_expired` | gauge | Products past EOL |

### Security

| Metric | Type | Description |
|--------|------|-------------|
| `linux_ssl_certificate_expiry_days` | gauge | Days until certificate expiry |
| `linux_ssl_certificates_total` | gauge | Certificates scanned |
| `linux_suid_files_total` | gauge | SUID files in system directories |
| `linux_sgid_files_total` | gauge | SGID files in system directories |
| `linux_journal_errors_24h` | gauge | Error-level journal entries (24h) |

### Operational

| Metric | Type | Description |
|--------|------|-------------|
| `linux_reboot_required` | gauge | System needs reboot (1=yes) |
| `linux_systemd_failed_units` | gauge | Failed systemd services |
| `linux_ntp_synced` | gauge | NTP synchronization status |
| `linux_firewall_active` | gauge | Firewall active status |
| `linux_listening_port` | gauge | TCP listening ports with process |
| `linux_docker_*` | gauge | Docker containers and images |

## Grafana Dashboard

A comprehensive Grafana dashboard is included (`grafana-linux-inventory-dashboard.json`) with:

### Executive Summary
- Host count, total packages, pending updates
- Journal errors, expiring certificates, reboot status
- Compliance gauges (patch, security, firewall, NTP)

### End-of-Life Tracking
- Products by status (supported/warning/EOL)
- Days until EOL visualization
- Detailed product table with version drift

### Fleet Overview
- Host inventory table with all system details
- OS and kernel distribution charts

### Security & Certificates
- SSL certificate expiry timeline
- SUID/SGID file counts
- Journal error trends

### Package Management
- Updates pending by host
- Security updates breakdown
- Package version drift detection
- Recently installed packages

### Docker & Containers
- Container status per host
- Image counts

### Network
- Listening ports across fleet
- Root filesystem usage
- Uptime tracking

## Grafana Alloy Integration

The included `config.alloy.tmpl` configures Grafana Alloy to:

1. Scrape the textfile collector directory
2. Filter metrics to `linux_*` namespace
3. Forward to Prometheus remote write endpoint

```alloy
prometheus.exporter.unix "software_inventory" {
  set_collectors = ["textfile"]
  textfile {
    directory = "/var/lib/prometheus/node-exporter"
  }
}

prometheus.scrape "software_inventory" {
  scrape_interval = "1m"
  targets         = discovery.relabel.software_inventory.output
  forward_to      = [prometheus.relabel.software_inventory.receiver]
}
```
## Deployment Options

### Installer Flags

```bash
deploy-inventory.sh [OPTIONS]

Options:
  --no-cron       Skip cron job creation
  --no-fetch      Skip EOL API fetch (use if no internet)
  --no-run        Skip initial inventory run
  --uninstall     Remove everything
  --dir <path>    Install directory (default: /data/software/application_scripts/software_inventory)
  --cron <expr>   Cron schedule (default: "0 */6 * * *")
```

### Uninstall

```bash
sudo ./deploy-inventory.sh --uninstall
```

## Troubleshooting

### No EOL Data

If EOL metrics show `status="no_data"`:
1. Ensure `jq` is installed
2. Check internet connectivity to endoflife.date
3. Verify `eol-full.json` exists and is valid JSON
4. Check cache directory permissions

### Missing Packages

If packages aren't appearing:
1. Run script as root for full access
2. Check package manager availability (`rpm -qa` or `dpkg -l`)
3. Verify output file permissions

### Certificate Scanning Fails

If SSL metrics are missing:
1. Install OpenSSL: `sudo dnf install openssl`
2. Check certificate directory permissions
3. Verify certificates are valid X.509 format

### Script Execution Time

The script runs EOL checks in parallel for performance. If it's slow:
1. Check network connectivity to endoflife.date
2. Use the full dump (`eol-full.json`) instead of per-product cache
3. Reduce certificate scan depth

## Performance

| Metric | Typical Value |
|--------|---------------|
| Execution time | 5-30 seconds |
| Output file size | 500KB - 2MB |
| Memory usage | < 50MB |
| API calls (full dump mode) | 0 per run |
| API calls (legacy mode) | 1 per product |

## Contributing

1. Fork the repository
2. Create a feature branch
3. Add tests for new functionality
4. Submit a pull request


## Credits

- EOL data provided by [endoflife.date](https://endoflife.date)
- Dashboard designed for Grafana 10+
- Compatible with Prometheus, VictoriaMetrics, Mimir

## Related Projects

- [Grafana Alloy](https://grafana.com/docs/alloy/latest/)
- [node_exporter](https://github.com/prometheus/node_exporter)
- [endoflife.date](https://github.com/endoflife-date/endoflife.date)