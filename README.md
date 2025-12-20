# Grafana Alloy installer script

**Automated, rerunnable installer + config generator for Grafana Alloy on Debian/Ubuntu.**

Run one script, select “packs” (pre-configured metrics/log collectors), enter your Prometheus and/or Loki endpoints, and it generates `/etc/alloy/config.alloy` and reloads Alloy.


## Quick start

```bash
git clone https://github.com/Unknowlars/Grafana-alloy-bootstrap.git
cd Grafana-alloy-bootstrap/alloy-bootstrap
chmod +x setup.sh
sudo ./setup.sh
```
---

## What it changes on your system

On each run it:

- Write (with timestamped backups):
  - `/etc/alloy/config.alloy`
  - `/etc/default/alloy`
- Store your last answers (defaults for next run):
  - `/var/lib/alloy-bootstrap/state.env`
- Enable + reload/restart:
  - `alloy.service`
- Add the `alloy` user to groups required by selected packs (e.g. `docker`, `systemd-journal`, `adm`)

> **Security note:** enabling some packs changes what the Alloy service user can access (especially Docker + system logs). Only enable what you need.

---

## How it works

- Discovers packs from `templates/packs/*/pack.conf`
- You select packs in a menu
- It renders templates with `envsubst`
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

```bash
sudo ./setup.sh --debug
sudo ./setup.sh --no-install
```

- `--debug`: shell trace (`set -x`)
- `--no-install`: skip Alloy APT install/upgrade checks
---

## Exposing the Alloy UI (security)

If you answer “yes” to exposing the UI, the script writes this to `/etc/default/alloy`:

```bash
CUSTOM_ARGS="--server.http.listen-addr=0.0.0.0:12345"
```

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