# AGENTS.md - Guidance for Agentic Coding in This Repository

This repository contains a bash shell script (`setup.sh`) for bootstrapping and configuring Grafana Alloy, along with Alloy configuration templates.

## Project Overview

- **Main script**: `alloy-bootstrap/setup.sh` (930 lines)
- **Templates**: `alloy-bootstrap/templates/packs/*/` and `alloy-bootstrap/templates/sinks/`
- **Purpose**: Automated, rerunnable installer + config generator for Grafana Alloy on Debian/Ubuntu
- **Language**: Bash (POSIX-compatible where possible)

---

## Build / Run Commands

### Running the Setup Script

```bash
# Interactive mode (default)
sudo ./alloy-bootstrap/setup.sh

# Non-interactive / silent mode
sudo ./alloy-bootstrap/setup.sh --non-interactive \
  --packs host-metrics,host-logs,docker \
  --prom-base-url http://192.168.0.123:9090 \
  --loki-base-url http://192.168.0.123:3400

# With debug output
sudo ./alloy-bootstrap/setup.sh --debug
```

### Linting

This project uses **shellcheck** for linting bash scripts:

```bash
# Lint the main script
shellcheck alloy-bootstrap/setup.sh

# Lint with specific rules enabled
shellcheck -S error alloy-bootstrap/setup.sh

# Enable all optional checks
shellcheck -o all alloy-bootstrap/setup.sh
```

### Testing

**There are currently no automated tests** in this repository. To validate changes:

```bash
# Syntax check the script
bash -n alloy-bootstrap/setup.sh

# Run with --debug to trace execution
sudo ./alloy-bootstrap/setup.sh --debug

# Validate generated Alloy config
alloy fmt --check /etc/alloy/config.alloy
```

---

## Code Style Guidelines

### Shell Script Conventions

1. **Strict Mode**: Always use at the top of scripts:
   ```bash
   set -eEuo pipefail
   ```

2. **Inherit Errexit** (bash 5+):
   ```bash
   if shopt -s inherit_errexit 2>/dev/null; then :; fi
   ```

3. **Error Trapping**: Include a trap for useful error messages:
   ```bash
   trap 'rc=$?; if ((rc!=0)); then echo "ERROR: failed (exit=$rc) near line $LINENO: $BASH_COMMAND" >&2; fi' EXIT
   ```

### Functions

- Use `local` for all variables inside functions
- Use `local -a` for arrays, `local -A` for associative arrays
- Place helper functions at the top or in a dedicated section
- Prefix internal/private functions with underscore if needed

### Variables

- Use `snake_case` for variable names: `PACKS_DIR`, `CFG_FILE`
- Use `SCREAMING_SNAKE_CASE` for constants: `PROM_REMOTE_WRITE_PATH`
- Always quote variables containing paths or user input: `"$VAR"`
- Declare associative arrays with `declare -A`
- Use `${VAR:-default}` for defaults, `${VAR:?error}` for required vars

### Sections and Organization

Use this section header format:
```bash
# =========================
# Section Name
# =========================
```

### Comments

- Use `#` for single-line comments
- Document complex regex or parsing logic inline
- Explain "why" not "what" in comments
- Disable shellcheck rules with inline comments when necessary:
  ```bash
  # shellcheck disable=SC1090
  source "$ENV_FILE" || true
  ```

### Naming Conventions

| Element | Convention | Example |
|---------|------------|---------|
| Variables | snake_case | `cfg_file`, `last_prom_base_url` |
| Functions | snake_case | `backup_file()`, `load_state()` |
| Constants | SCREAMING_SNAKE_CASE | `CFG_DIR`, `STATE_FILE` |
| Packs | kebab-case | `host-metrics`, `docker` |

### Error Handling

- Use helper functions:
  ```bash
  err()  { echo "ERROR: $*" >&2; exit 1; }
  warn() { echo "WARN:  $*" >&2; }
  info() { echo "==> $*"; }
  ```
- Check for required commands: `has_cmd() { command -v "$1" >/dev/null 2>&1; }`
- Validate required arguments before processing
- Use descriptive error messages including the failing command/value

### Argument Parsing

- Support both `--flag` and `--flag=value` syntax
- Use a `while` loop with `case` for argument parsing
- Handle unknown arguments with error message and exit code 2

### Template Files

Pack configurations use simple `key=value` format (`pack.conf`):
```
id=host-metrics
title=Host metrics (node_exporter)
signals=metrics
requires_group=docker
vars=VAR:Prompt:Default
```

Alloy templates use `envsubst` syntax:
```
prometheus.scrape "integrations_node_exporter" {
  scrape_interval = "15s"
  targets         = discovery.relabel.integrations_node_exporter.output
  forward_to      = [prometheus.remote_write.local.receiver]
}
```

### Best Practices

- **Quotes**: Always quote variables unless you explicitly need word splitting
- **Exit codes**: Use `exit 0` for success, `exit 1` for errors, `exit 2` for usage errors
- **Redirection**: Use `>/dev/null 2>&1` to suppress output, `>&2` for errors
- **Command substitution**: Use `$(...)` over backticks
- **Permissions**: Set restrictive permissions on state files: `chmod 600 "$STATE_FILE"`
- **Idempotency**: Make scripts rerunnable without side effects
- **State management**: Save and restore state between runs for non-interactive use

---

## Common Tasks

### Adding a New Pack

1. Create directory: `alloy-bootstrap/templates/packs/<NN>-<pack-id>/`
2. Create `pack.conf` with id, title, signals, optionally requires_group and vars
3. Create `config.alloy.tmpl` with the Alloy configuration snippet
4. Test interactively: `sudo ./alloy-bootstrap/setup.sh`

### Modifying Existing Packs

1. Edit the pack's `pack.conf` or `config.alloy.tmpl`
2. Run setup to regenerate config: `sudo ./alloy-bootstrap/setup.sh`
3. Verify: `alloy fmt --check /etc/alloy/config.alloy`

### Debugging

```bash
# Enable trace
sudo ./alloy-bootstrap/setup.sh --debug

# Check Alloy config manually
sudo alloy fmt --check /etc/alloy/config.alloy
sudo alloy validate /etc/alloy/config.alloy

# View Alloy logs
journalctl -u alloy -n 200 --no-pager
```

---

## Additional Resources

- [ShellCheck](https://www.shellcheck.net/) - Bash linting tool
- [Bash Strict Mode](http://redsymbol.net/articles/unset-or-use-bash-strict-mode/) - Error handling best practices
- [Grafana Alloy Docs](https://grafana.com/docs/alloy/) - Configuration reference
