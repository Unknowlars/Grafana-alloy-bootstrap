# Contributing to Grafana-alloy-bootstrap

Thank you for your interest in contributing! This guide will help you get started.

## Code of Conduct

Please read and follow our [Code of Conduct](CODE_OF_CONDUCT.md) to keep our community welcoming and respectful.

## How to Contribute

### Reporting Bugs

1. **Check existing issues** - Someone may have already reported the same problem
2. **Create a new issue** using the bug template
3. **Include details**:
   - Your OS and version (e.g., Ubuntu 22.04)
   - Alloy version (`alloy --version`)
   - Steps to reproduce
   - Any relevant logs (`journalctl -u alloy -n 50`)

### Suggesting Features

1. Open an issue with the feature request template
2. Describe the use case - *why* do you need this?
3. Explain how it should work

### Pull Requests

#### Prerequisites

- A Debian/Ubuntu system for testing
- `shellcheck` installed locally: `apt-get install shellcheck`
- Basic knowledge of Grafana Alloy configuration

#### Development Setup

```bash
git clone https://github.com/Unknowlars/Grafana-alloy-bootstrap.git
cd Grafana-alloy-bootstrap

# Install shellcheck for local linting
apt-get install shellcheck

# Test syntax locally
bash -n alloy-bootstrap/setup.sh

# Run shellcheck
shellcheck alloy-bootstrap/setup.sh
```

#### Adding a New Pack

Packs are the easiest way to contribute! Here's how:

1. **Create the pack directory**:
   ```bash
   mkdir -p alloy-bootstrap/templates/packs/<NN>-<pack-id>/
   ```
   - Use a number prefix (`10-`, `20-`, etc.) to control display order
   - Use kebab-case for the pack ID (e.g., `50-my-feature`)

2. **Create `pack.conf`** - metadata for the menu:
   ```bash
   # alloy-bootstrap/templates/packs/50-my-feature/pack.conf
   id=my-feature
   title=My Feature Description
   signals=metrics  # metrics, logs, metrics,logs, or none
   requires_group=  # optional: add alloy user to group
   vars=VAR_NAME:Prompt:Default  # optional: pack-specific variables
   ```

3. **Create `config.alloy.tmpl`** - the Alloy configuration:
   ```bash
   # alloy-bootstrap/templates/packs/50-my-feature/config.alloy.tmpl
   discovery.relabel "my_feature" {
     # Your Alloy configuration here
   }
   ```
   
   Available variables you can use:
   - `${PROM_REMOTE_WRITE_URL}` - Prometheus remote write endpoint
   - `${LOKI_PUSH_URL}` - Loki push endpoint
   - `${VAR_NAME}` - Any custom variables from pack.conf

4. **Test your pack**:
   ```bash
   sudo ./alloy-bootstrap/setup.sh
   ```

#### Pull Request Guidelines

1. **Keep PRs focused** - One feature or fix per PR
2. **Run checks before submitting**:
   ```bash
   # Syntax check
   bash -n alloy-bootstrap/setup.sh
   
   # Lint
   shellcheck alloy-bootstrap/setup.sh
   ```
3. **Update documentation** if needed (README.md, this file)
4. **Use clear commit messages**:
   - `add: new pack for X service`
   - `fix: resolve issue with Y configuration`
   - `docs: update README with Z`

## Style Guide

See [AGENTS.md](AGENTS.md) for detailed coding standards:
- Strict bash mode (`set -eEuo pipefail`)
- Proper error handling with `err()`, `warn()`, `info()`
- Snake_case for variables, SCREAMING_SNAKE_CASE for constants

## Recognition

Contributors will be mentioned in the README (with permission).

## Questions?

- Open an issue for bugs or feature requests
- For general questions, start a GitHub Discussion
