# Grafana Alloy installer script

**Automated, rerunnable installer + config generator for Grafana Alloy on Debian/Ubuntu.**

Run one script, select “packs” (pre-configured metrics/log collectors), enter your Prometheus and/or Loki endpoints, and it generates `/etc/alloy/config.alloy` and reloads Alloy.

This project supports **both interactive** (menu + prompts) and **non-interactive / silent** installs (CLI flags), which is useful for automation/provisioning.


## Quick start

```bash
git clone https://github.com/Unknowlars/Grafana-alloy-bootstrap.git
cd Grafana-alloy/alloy-bootstrap
chmod +x setup.sh
sudo ./setup.sh
```

---

## Interactive mode (default)

Interactive mode shows a menu of packs and prompts you for required settings (Prometheus/Loki endpoints, pack variables, optional UI bind).

### Example interactive run

```bash
./setup.sh

==> Starting alloy-bootstrap setup (rerunnable) ...
==> Alloy installed version: 1.12.1-1
==> Alloy APT candidate:     1.12.1-1
==> Alloy is up to date (or no candidate available).

Available collection packs:

   1) [x] Host metrics (node_exporter)  [metrics]
   2) [x] Host logs (journald + /var/log)  [logs]
   3) [x] Docker containers (cAdvisor metrics + docker logs)  [metrics,logs]
   4) [ ] Scrape logporter metrics (custom Prometheus scrape)  [metrics]
   5) [ ] Postgres exporter scrape  [metrics]
   6) [ ] Traefik metrics scrape (integrations/traefik)  [metrics]
   7) [ ] Traefik access logs (file) -> GeoIP country label -> Loki  [logs]
   8) [ ] Enable livedebugging (Alloy UI debug stream)  [none]

Previously enabled packs: host-metrics host-logs docker

Select packs by number (space-separated) [1 2 3]: 1 2 3

Prometheus/VictoriaMetrics base (previous: http://192.168.0.123:9090) — enter http(s)://host:port or host:port [http://192.168.0.123:9090]:
==> Using Prometheus/VictoriaMetrics base: http://192.168.0.123:9090

Loki base (previous: http://192.168.0.123:3400) — enter http(s)://host:port or host:port [http://192.168.0.123:3400]:
==> Using Loki base: http://192.168.0.123:3400

==> Pack-specific settings:
Expose Alloy HTTP UI on network (sets --server.http.listen-addr)? [y/N]: y
Listen address (host:port) [127.0.0.1:12345]:
==> Using Alloy UI listen addr: 127.0.0.1:12345
==> Backed up /etc/default/alloy -> /etc/default/alloy.bak.20251220-224151
==> Wrote /etc/default/alloy
==> Backed up /etc/alloy/config.alloy -> /etc/alloy/config.alloy.bak.20251220-224151
==> Installed validated config to /etc/alloy/config.alloy
==> User 'alloy' already in group 'docker'.
==> User 'alloy' already in group 'systemd-journal'.
==> User 'alloy' already in group 'adm'.
==> Reloaded Alloy.
==> Saved state to /var/lib/alloy-bootstrap/state.env
==> Done. Run again anytime after git pull or when adding packs.
  Prom remote_write: http://192.168.0.123:9090/api/v1/write
  Loki push:         http://192.168.0.123:3400/loki/api/v1/push
  Alloy UI listen:   127.0.0.1:12345
```

---

## Non-interactive / silent mode

Silent mode skips all prompts. You provide everything via CLI flags (or it reuses values from the saved state file).

### Example silent run

```bash
sudo ./setup.sh --non-interactive \
  --packs host-metrics,host-logs,docker \
  --prom-base-url http://192.168.0.123:8429 \
  --loki-base-url http://192.168.0.238:3400 \
  --ui-listen-addr 127.0.0.1:12345
```

### How silent mode resolves values

- **Packs**:
  - Use `--packs ...` if provided
  - Otherwise reuse `LAST_SELECTED_PACK_IDS` from `/var/lib/alloy-bootstrap/state.env` (if present)
- **Prometheus/Loki endpoints**:
  - Use `--prom-base-url` / `--loki-base-url` if provided
  - Otherwise reuse `LAST_PROM_BASE_URL` / `LAST_LOKI_BASE_URL` from state (if present)
  - If you selected a metrics/logs pack but no endpoint can be resolved, the script exits with an error.
- **Pack variables** (`vars=` in `pack.conf`):
  - Highest priority: existing environment variable (e.g. `LOGPORTER_ADDR=...`)
  - Next: `--var NAME=value`
  - Next: default value from the pack (`vars=NAME:Prompt:Default`)
  - If no value can be resolved and there is no default, the script exits with an error.
- **Alloy UI listen address**:
  - Use `--ui-listen-addr host:port` to enable it
  - Use `--no-ui` to force-disable it

### Pack variable examples

```bash
sudo ./setup.sh --non-interactive \
  --packs logporter \
  --prom-base-url http://192.168.0.123:8429 \
  --var LOGPORTER_ADDR=192.168.0.50:9999
```

Or with environment variables:

```bash
export LOGPORTER_ADDR="192.168.0.50:9999"
sudo ./setup.sh --non-interactive --packs logporter --prom-base-url http://192.168.0.123:8429
```

---

## What it changes on your system

On each run it:

- Writes (with timestamped backups):
  - `/etc/alloy/config.alloy`
  - `/etc/default/alloy`
- Stores your last answers (defaults for next run):
  - `/var/lib/alloy-bootstrap/state.env`
- Enables + reloads/restarts:
  - `alloy.service`
- Adds the `alloy` user to groups required by selected packs (e.g. `docker`, `systemd-journal`, `adm`)

> **Security note:** enabling some packs changes what the Alloy service user can access (especially Docker + system logs). Only enable what you need.

---

## How it works

- Discovers packs from `templates/packs/*/pack.conf`
- Interactive mode: you select packs in a menu
- Silent mode: packs/settings come from flags and/or saved state
- Renders templates with `envsubst`
- Writes a combined config:
  - shared **sinks** from `templates/sinks/`
  - selected **packs** from `templates/packs/`
- Formats (best-effort): `alloy fmt --write /etc/alloy/config.alloy`
- Reloads (or restarts) Alloy

---

## Available packs

> This table describes the packs currently shipped in this repo. Add/remove packs by editing `templates/packs/`.

| Pack | ID | Signals | Prompts | Notes |
|---|---|---:|---|---|
| Host metrics (node_exporter) | `host-metrics` | metrics | — | Requires Prom/VictoriaMetrics remote_write |
| Host logs (syslog + messages + auth + journald + /var/log) | `host-logs` | logs | — | Adds `alloy` to `systemd-journal` + `adm` |
| Docker (cAdvisor metrics + docker logs) | `docker` | metrics,logs | — | Adds `alloy` to `docker` group |
| Logporter scrape (custom Prometheus scrape) | `logporter` | metrics | `LOGPORTER_ADDR` | Scrapes HTTP promthues endpoint from logporter, check https://github.com/Lifailon/logporter |
| Postgres exporter scrape | `postgres` | metrics | `POSTGRES_EXPORTER_ADDR` | Scrapes postgres-exporter you provide |
| Traefik metrics scrape (integrations/traefik) | `traefik-metrics` | metrics | `TRAEFIK_METRICS_ADDR` | Scrapes Traefik metrics endpoint you provide |
| Live debugging (Alloy UI debug stream) | `livedebugging` | none | — | Debug-only; no Prom/Loki required |

**Signals:**
- `metrics` → you’ll be prompted for Promethues base URL and the script appends `/api/v1/write`
- `logs` → you’ll be prompted for Loki base URL and the script appends `/loki/api/v1/push`

---

## Options

### General options

```bash
sudo ./setup.sh --debug
sudo ./setup.sh --no-install
```

- `--debug`: shell trace (`set -x`)
- `--no-install`: skip Alloy APT install/upgrade checks

### Silent mode options

```bash
sudo ./setup.sh --non-interactive --packs host-metrics --prom-base-url http://192.168.0.123:8429
```

Flags:
- `--non-interactive` / `--silent`: no prompts (automation-friendly)
- `--yes`: answer “yes” to yes/no prompts (install/upgrade checks) in silent mode
- `--packs <id1,id2,...>`: comma/space-separated pack IDs
- `--prom-base-url <http(s)://host:port | host:port>`: Prometheus/VictoriaMetrics base
- `--loki-base-url <http(s)://host:port | host:port>`: Loki base
- `--ui-listen-addr <host:port>`: enable Alloy UI listen address
- `--no-ui`: force-disable Alloy UI
- `--var NAME=value`: pack variables (repeatable)

---

## Exposing the Alloy UI

If you enable the UI, the script writes this to `/etc/default/alloy`:

```bash
CUSTOM_ARGS="--server.http.listen-addr=0.0.0.0:12345"
```

Binding to `0.0.0.0` exposes the UI on the network. Prefer 127.0.0.1:12345
---

## Rollback / undo

Backups are created each run:

- `/etc/alloy/config.alloy.bak.<timestamp>`
- `/etc/default/alloy.bak.<timestamp>`

Restore and restart:

```bash
sudo cp -a /etc/alloy/config.alloy.bak.<timestamp> /etc/alloy/config.alloy
sudo cp -a /etc/default/alloy.bak.<timestamp> /etc/default/alloy
sudo systemctl restart alloy
```

Forget previous selections:

```bash
sudo rm -f /var/lib/alloy-bootstrap/state.env
```

---

## Packs for contributors

Each pack folder contains:

- `pack.conf` (metadata shown in the menu)
- `config.alloy.tmpl` (Alloy snippet rendered via `envsubst`)

### `pack.conf` keys

Required:
- `id=...`
- `title=...`
- `signals=metrics` or `logs` or `metrics,logs` or `none`

Optional:
- `requires_group=...` (script adds user `alloy` to the group)
- `vars=VAR:Prompt:Default,VAR2:Prompt:Default` (pack-specific prompts)

Templates can use variables like `${PROM_REMOTE_WRITE_URL}`, `${LOKI_PUSH_URL}`, and any vars from `vars=`.

---

## Useful commands

```bash
systemctl status alloy
journalctl -u alloy -n 200 --no-pager
sudo alloy fmt --check /etc/alloy/config.alloy
sudo systemctl reload alloy
sudo systemctl restart alloy
```
