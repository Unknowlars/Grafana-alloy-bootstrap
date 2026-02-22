# Grafana Alloy Bootstrap

[![CI](https://github.com/Unknowlars/Grafana-alloy-bootstrap/actions/workflows/ci.yml/badge.svg)](https://github.com/Unknowlars/Grafana-alloy-bootstrap/actions/workflows/ci.yml)
[![ShellCheck](https://img.shields.io/badge/ShellCheck-passing-brightgreen)](https://www.shellcheck.net/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![GitHub stars](https://img.shields.io/github/stars/Unknowlars/Grafana-alloy-bootstrap)](https://github.com/Unknowlars/Grafana-alloy-bootstrap/stargazers)

> Automated, rerunnable installer and configuration generator for Grafana Alloy on Debian/Ubuntu.

Run one script, select "packs" (pre-configured metrics/log collectors), enter your Prometheus/Loki endpoints, and it generates `/etc/alloy/config.alloy` and reloads Alloy.

---

## Features

- :rocket: **One-command setup** - Get Alloy running in minutes
- :repeat: **Idempotent** - Run multiple times safely; only applies changes when needed
- :computer: **Interactive & silent modes** - Menu-driven or automation-friendly CLI flags
- :package: **Modular packs** - Enable only what you need (host metrics, Docker, logs, etc.)
- :shield: **Automatic backups** - Timestamped backups before every change
- :test_tube: **CI tested** - ShellCheck validated on every change

---

## Quick Start

```bash
# Clone and run (one-liner)
git clone https://github.com/Unknowlars/Grafana-alloy-bootstrap.git && \
  cd Grafana-alloy-bootstrap && chmod +x alloy-bootstrap/setup.sh && \
  sudo ./alloy-bootstrap/setup.sh
```

The script will:
1. Check for/install Grafana Alloy (official APT repository)
2. Show a menu of available packs
3. Ask for Prometheus and Loki endpoints
4. Generate `/etc/alloy/config.alloy`
5. Enable and start the Alloy service

---

## Requirements

- **OS**: Debian-based Linux (Debian 11+, Ubuntu 20.04+, Raspberry Pi OS)
- **Permissions**: Root access (sudo)
- **Network**: Outbound access to your Prometheus/Loki endpoints

---

## Usage Modes

### Interactive Mode (Default)

```bash
sudo ./alloy-bootstrap/setup.sh
```

Shows a menu where you can:
- Select which packs to enable
- Configure Prometheus/Loki endpoints
- Enable the Alloy web UI

### Silent Mode (Automation)

Perfect for Docker, Ansible, Terraform, or cloud-init:

```bash
sudo ./alloy-bootstrap/setup.sh \
  --non-interactive \
  --packs host-metrics,host-logs,docker \
  --prom-base-url http://192.168.0.123:9090 \
  --loki-base-url http://192.168.0.123:3400 \
  --ui-listen-addr 127.0.0.1:12345
```

---

## Available Packs

| # | Pack | ID | Signals | Description |
|---|------|-----|---------|-------------|
| 1 | Host metrics | `host-metrics` | metrics | node_exporter for CPU, memory, disk, network |
| 2 | Host logs | `host-logs` | logs | journald, syslog, /var/log collection |
| 3 | Docker | `docker` | metrics,logs | cAdvisor + Docker container logs |
| 4 | Logporter | `logporter` | metrics | Custom Prometheus scrape target |
| 5 | PostgreSQL | `postgres` | metrics | postgres_exporter scrape |
| 6 | Traefik metrics | `traefik-metrics` | metrics | Traefik integrations |
| 7 | Traefik access logs | `traefik-access-logs-geoip` | logs | Access logs with GeoIP country labels |
| 8 | Software inventory | `software-inventory` | metrics | Linux packages, updates, system info |
| 9 | Live debugging | `livedebugging` | none | Alloy UI debug stream |

**Signal Types:**
- `metrics` - Requires Prometheus/VictoriaMetrics endpoint
- `logs` - Requires Loki endpoint
- `metrics,logs` - Requires both endpoints
- `none` - No external endpoint required

---

## Command-Line Options

### General Options

| Option | Description |
|--------|-------------|
| `--debug` | Enable shell trace (`set -x`) |
| `--no-install` | Skip Alloy APT install/upgrade checks |
| `-h, --help` | Show help message |

### Silent Mode Options

| Option | Description |
|--------|-------------|
| `--non-interactive` | Run without prompts |
| `--yes` | Auto-answer "yes" to prompts |
| `--packs <ids>` | Comma-separated pack IDs |
| `--prom-base-url <url>` | Prometheus/VictoriaMetrics base URL |
| `--loki-base-url <url>` | Loki base URL |
| `--ui-listen-addr <addr>` | Enable Alloy UI (e.g., `127.0.0.1:12345`) |
| `--no-ui` | Force-disable Alloy UI |
| `--var NAME=value` | Pack-specific variable (repeatable) |

### Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `STABILITY_LEVEL` | Alloy stability track | `generally-available` |
| `COMMUNITY_COMPONENTS` | Enable community components | `false` |

---

## What It Changes

On each run, the script:

1. **Writes configuration** (with timestamped backups):
   - `/etc/alloy/config.alloy` - Alloy configuration
   - `/etc/default/alloy` - Alloy environment variables

2. **Saves state** (for next run defaults):
   - `/var/lib/alloy-bootstrap/state.env`

3. **Manages service**:
   - Enables and starts `alloy.service`
   - Reloads or restarts as needed

4. **Sets permissions**:
   - Adds `alloy` user to required groups (`docker`, `systemd-journal`, etc.)

---

## How It Works

```
┌─────────────────┐
│  User runs      │
│  setup.sh       │
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│  Discover packs │
│  from templates │
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│  User selects   │
│  packs (menu)   │
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│  Prompt for     │
│  endpoints      │
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│  envsubst       │
│  templates      │
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│  Write config   │
│  with backups   │
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│  Restart Alloy  │
│  service        │
└─────────────────┘
```

Packs are discovered from `templates/packs/*/pack.conf` and rendered using `envsubst`. Each pack provides a modular snippet that can be independently enabled or disabled.

---

## Troubleshooting

### Check Alloy Status

```bash
systemctl status alloy
journalctl -u alloy -n 100 --no-pager
```

### Validate Configuration

```bash
alloy validate /etc/alloy/config.alloy
alloy fmt --check /etc/alloy/config.alloy
```

### Debug Mode

```bash
sudo ./alloy-bootstrap/setup.sh --debug
```

### Rollback

Backups are created automatically:
```bash
# Find backups
ls -la /etc/alloy/config.alloy.bak.*

# Restore
sudo cp /etc/alloy/config.alloy.bak.20251220-224151 /etc/alloy/config.alloy
sudo systemctl restart alloy
```

### Reset State

```bash
sudo rm -f /var/lib/alloy-bootstrap/state.env
```

---

## Contributing

Contributions are welcome! Please see [CONTRIBUTING.md](CONTRIBUTING.md) for:

- How to set up a development environment
- How to add a new pack
- Coding standards (in [AGENTS.md](AGENTS.md))
- Pull request process

---

## Security

See [SECURITY.md](SECURITY.md) for our security policy and how to report vulnerabilities.

---

## License

Released under the [MIT License](LICENSE).

---

## Resources

- [Grafana Alloy Documentation](https://grafana.com/docs/alloy/)
- [ShellCheck](https://www.shellcheck.net/) - Bash linting
- [Alloy Configuration Reference](https://grafana.com/docs/alloy/reference/configuration/)
