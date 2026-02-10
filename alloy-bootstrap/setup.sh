#!/usr/bin/env bash
set -eEuo pipefail

# Make `set -e` propagate into more contexts (bash 5+)
if shopt -s inherit_errexit 2>/dev/null; then :; fi

# Print a useful error on non-zero exit
trap 'rc=$?; if ((rc!=0)); then echo "ERROR: failed (exit=$rc) near line $LINENO: $BASH_COMMAND" >&2; fi' EXIT

# =========================
# Paths
# =========================
SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
PACKS_DIR="${SCRIPT_DIR}/templates/packs"
SINKS_DIR="${SCRIPT_DIR}/templates/sinks"

CFG_DIR="/etc/alloy"
CFG_FILE="/etc/alloy/config.alloy"
ENV_FILE="/etc/default/alloy"

PROM_REMOTE_WRITE_PATH="/api/v1/write"
LOKI_PUSH_PATH="/loki/api/v1/push"

# Persist last answers here (per-machine)
STATE_DIR="/var/lib/alloy-bootstrap"
STATE_FILE="${STATE_DIR}/state.env"

DEBUG=0
NO_INSTALL=0

# New CLI controls
NONINTERACTIVE=0
AUTO_YES=0

PACKS_ARG=""
PROM_BASE_URL_ARG=""
LOKI_BASE_URL_ARG=""
UI_LISTEN_ADDR_ARG=""
NO_UI=0

declare -A CLI_VARS=()

STABILITY_LEVEL="${STABILITY_LEVEL:-generally-available}"
COMMUNITY_COMPONENTS="${COMMUNITY_COMPONENTS:-false}"

# Public-friendly defaults
DEFAULT_PROM_BASE_URL="${DEFAULT_PROM_BASE_URL:-http://YOUR_PROMETHEUS_IP_OR_DNS_NAME:PORT}"
DEFAULT_LOKI_BASE_URL="${DEFAULT_LOKI_BASE_URL:-http://YOUR_LOKI_IP_OR_DNS_NAME:PORT}"

# =========================
# Helpers
# =========================
err()  { echo "ERROR: $*" >&2; exit 1; }
warn() { echo "WARN:  $*" >&2; }
info() { echo "==> $*"; }

need_root() { [[ "${EUID}" -eq 0 ]] || err "Run as root: sudo $0"; }
has_cmd() { command -v "$1" >/dev/null 2>&1; }

trim() {
  sed -e 's/^[[:space:]]*//' -e 's/[[:space:]]*$//'
}

usage() {
  cat <<'EOF'
Usage:
  setup.sh [options]

Interactive (default):
  sudo ./setup.sh

Non-interactive / silent:
  sudo ./setup.sh --non-interactive --packs host-metrics,host-logs,docker \
    --prom-base-url http://192.168.0.123:9090 \
    --loki-base-url http://192.168.0.123:3400 \
    --ui-listen-addr 127.0.0.1:12345

Options:
  --non-interactive, --silent   Run without prompts (uses flags/state/defaults)
  --yes                         Answer "yes" to yes/no prompts in silent mode

  --packs <ids>                 Comma/space-separated pack IDs (e.g. docker,host-logs)
                                If omitted in silent mode, uses LAST_SELECTED_PACK_IDS if present

  --prom-base-url <url>         Prom/Victoria base URL (http(s)://host:port or host:port)
  --loki-base-url <url>         Loki base URL (http(s)://host:port or host:port)

  --ui-listen-addr <host:port>  Enable UI and set --server.http.listen-addr
  --no-ui                        Force disable UI even if state had it

  --var NAME=value               Provide pack vars (repeatable)

  --debug                        set -x
  --no-install                   skip APT install/upgrade checks
  -h, --help                     show this help
EOF
}

parse_kv_var() {
  local kv="$1"
  [[ "$kv" == *"="* ]] || err "--var expects NAME=value (got: $kv)"
  local k="${kv%%=*}"
  local v="${kv#*=}"
  k="$(echo "$k" | trim)"
  [[ -n "$k" ]] || err "--var expects NAME=value (empty NAME)"
  CLI_VARS["$k"]="$v"
}

# =========================
# Args
# =========================
while [[ $# -gt 0 ]]; do
  case "$1" in
    --debug) DEBUG=1 ;;
    --no-install) NO_INSTALL=1 ;;
    --non-interactive|--silent) NONINTERACTIVE=1 ;;
    --yes|--assume-yes) AUTO_YES=1 ;;
    --packs)
      shift
      [[ $# -gt 0 ]] || err "--packs requires a value"
      PACKS_ARG="$1"
      ;;
    --packs=*) PACKS_ARG="${1#*=}" ;;
    --prom-base-url)
      shift
      [[ $# -gt 0 ]] || err "--prom-base-url requires a value"
      PROM_BASE_URL_ARG="$1"
      ;;
    --prom-base-url=*) PROM_BASE_URL_ARG="${1#*=}" ;;
    --loki-base-url)
      shift
      [[ $# -gt 0 ]] || err "--loki-base-url requires a value"
      LOKI_BASE_URL_ARG="$1"
      ;;
    --loki-base-url=*) LOKI_BASE_URL_ARG="${1#*=}" ;;
    --ui-listen-addr)
      shift
      [[ $# -gt 0 ]] || err "--ui-listen-addr requires a value"
      UI_LISTEN_ADDR_ARG="$1"
      ;;
    --ui-listen-addr=*) UI_LISTEN_ADDR_ARG="${1#*=}" ;;
    --no-ui) NO_UI=1 ;;
    --var)
      shift
      [[ $# -gt 0 ]] || err "--var requires NAME=value"
      parse_kv_var "$1"
      ;;
    --var=*) parse_kv_var "${1#*=}" ;;
    -h|--help) usage; exit 0 ;;
    *)
      echo "Unknown arg: $1" >&2
      usage >&2
      exit 2
      ;;
  esac
  shift || true
done

if [[ "$DEBUG" -eq 1 ]]; then
  set -x
fi

backup_file() {
  local f="$1"
  if [[ -f "$f" ]]; then
    local ts; ts="$(date +%Y%m%d-%H%M%S)"
    cp -a "$f" "${f}.bak.${ts}"
    info "Backed up $f -> ${f}.bak.${ts}"
  fi
}

ask_yes_no() {
  local prompt="$1" default="${2:-y}" ans
  local hint="[y/n]"
  [[ "$default" == "y" ]] && hint="[Y/n]"
  [[ "$default" == "n" ]] && hint="[y/N]"

  if [[ "${NONINTERACTIVE}" -eq 1 ]]; then
    if [[ "${AUTO_YES}" -eq 1 ]]; then return 0; fi
    [[ "$default" == "y" ]] && return 0 || return 1
  fi

  while true; do
    read -r -p "$prompt $hint: " ans || true
    ans="${ans:-$default}"
    case "$ans" in
      y|Y) return 0 ;;
      n|N) return 1 ;;
      *) echo "Please answer y or n." ;;
    esac
  done
}

ask_input() {
  local prompt="$1" default="${2:-}" value

  if [[ "${NONINTERACTIVE}" -eq 1 ]]; then
    echo "$default"
    return 0
  fi

  if [[ -n "$default" ]]; then
    read -r -p "$prompt [$default]: " value || true
    echo "${value:-$default}"
  else
    read -r -p "$prompt: " value || true
    echo "$value"
  fi
}

ask_nonempty() {
  local prompt="$1" default="${2:-}" value
  while true; do
    value="$(ask_input "$prompt" "$default")"
    value="$(echo "$value" | trim)"
    [[ -n "$value" ]] && { echo "$value"; return 0; }
    if [[ "${NONINTERACTIVE}" -eq 1 ]]; then
      err "Missing required value for: $prompt (provide via flags or state/defaults)"
    fi
    echo "Please enter a value."
  done
}

normalize_base_url() {
  local in="$1"
  in="$(echo "$in" | trim)"
  if [[ "$in" =~ ^https?:// ]]; then
    echo "${in%/}"
    return 0
  fi
  if [[ "$in" =~ ^[^/]+:[0-9]+$ ]]; then
    echo "http://${in}"
    return 0
  fi
  return 1
}

validate_base_url() {
  local u="$1"
  [[ "$u" =~ ^https?://[^/]+$ ]] || return 1
  return 0
}

join_url_path() {
  local base="$1" path="$2"
  base="${base%/}"
  path="/${path#/}"
  echo "${base}${path}"
}

validate_listen_addr() {
  local a="$1"
  [[ "$a" =~ ^[^:]+:[0-9]+$ ]] || return 1
  return 0
}

dedup_lines() { awk '!seen[$0]++'; }

# Read current CUSTOM_ARGS from /etc/default/alloy (if present).
# This allows us to restart Alloy when runtime args change (reload won't apply).
read_current_custom_args() {
  local cur=""
  if [[ -f "$ENV_FILE" ]]; then
    # shellcheck disable=SC1090
    source "$ENV_FILE" >/dev/null 2>&1 || true
    cur="${CUSTOM_ARGS:-}"
  fi
  echo "$cur"
}

# =========================
# State (remember last run defaults)
# =========================
load_state() {
  mkdir -p "$STATE_DIR"
  if [[ -f "$STATE_FILE" ]]; then
    # shellcheck disable=SC1090
    source "$STATE_FILE" || true
  fi
}

save_state() {
  mkdir -p "$STATE_DIR"
  cat > "$STATE_FILE" <<EOF
# Managed by alloy-bootstrap setup.sh
LAST_PROM_BASE_URL="${LAST_PROM_BASE_URL:-}"
LAST_LOKI_BASE_URL="${LAST_LOKI_BASE_URL:-}"
LAST_UI_LISTEN_ADDR="${LAST_UI_LISTEN_ADDR:-}"
LAST_SELECTED_PACK_IDS="${LAST_SELECTED_PACK_IDS:-}"
EOF
  chmod 600 "$STATE_FILE" || true
  info "Saved state to $STATE_FILE"
}

# =========================
# pack.conf parser
# =========================
load_pack_conf() {
  local file="$1"
  id="" title="" signals="" requires_cmd="" requires_group="" vars=""

  while IFS= read -r line || [[ -n "$line" ]]; do
    line="${line%%#*}"
    line="${line%%;*}"
    [[ -z "${line//[[:space:]]/}" ]] && continue
    [[ "$line" =~ ^[a-zA-Z_][a-zA-Z0-9_]*= ]] || continue

    local key="${line%%=*}"
    local val="${line#*=}"
    key="$(echo "$key" | trim)"
    val="$(echo "$val" | trim)"

    case "$key" in
      id) id="$val" ;;
      title) title="$val" ;;
      signals) signals="$val" ;;
      requires_cmd) requires_cmd="$val" ;;
      requires_group) requires_group="$val" ;;
      vars) vars="$val" ;;
      *) warn "Unknown key '$key' in $file (ignored)" ;;
    esac
  done < "$file"

  [[ -n "$id" && -n "$title" && -n "$signals" ]] || err "Invalid pack.conf (need id/title/signals): $file"
}

ensure_envsubst() {
  if has_cmd envsubst; then return 0; fi
  info "Installing envsubst (gettext-base)..."
  apt-get update -y
  apt-get install -y gettext-base
}

# ENVSUBST_VARS
render_template() {
  local tmpl="$1"
  if [[ -n "${ENVSUBST_VARS:-}" ]]; then
    envsubst "$ENVSUBST_VARS" < "$tmpl"
  else
    envsubst '' < "$tmpl"
  fi
}

# =========================
# Alloy install/upgrade checks
# =========================
have_alloy_installed() { dpkg -s alloy >/dev/null 2>&1; }
alloy_installed_version() { dpkg-query -W -f='${Version}\n' alloy 2>/dev/null || true; }
alloy_candidate_version() { apt-cache policy alloy 2>/dev/null | awk '/Candidate:/{print $2; exit}' || true; }

install_or_upgrade_alloy_apt() {
  info "Installing/upgrading Grafana Alloy via APT..."
  apt-get update -y
  apt-get install -y gpg wget ca-certificates apt-transport-https

  if [[ ! -f /etc/apt/sources.list.d/grafana.list ]] || [[ ! -f /etc/apt/keyrings/grafana.gpg ]]; then
    mkdir -p /etc/apt/keyrings/
    wget -q -O - https://apt.grafana.com/gpg.key | gpg --dearmor | tee /etc/apt/keyrings/grafana.gpg > /dev/null
    echo "deb [signed-by=/etc/apt/keyrings/grafana.gpg] https://apt.grafana.com stable main" \
      | tee /etc/apt/sources.list.d/grafana.list > /dev/null
  fi

  apt-get update -y
  apt-get install -y alloy
  systemctl enable --now alloy.service >/dev/null 2>&1 || true
}

maybe_install_or_upgrade_alloy() {
  if [[ "$NO_INSTALL" -eq 1 ]]; then
    info "--no-install set: skipping Alloy install/upgrade checks."
    return 0
  fi

  if ! have_alloy_installed; then
    if ask_yes_no "Grafana Alloy is not installed. Install it now?" "y"; then
      install_or_upgrade_alloy_apt
      return 0
    else
      err "Alloy not installed; cannot continue."
    fi
  fi

  local installed candidate
  installed="$(alloy_installed_version)"
  candidate="$(alloy_candidate_version)"

  info "Alloy installed version: ${installed:-unknown}"
  info "Alloy APT candidate:     ${candidate:-unknown}"

  if [[ -n "$candidate" && "$candidate" != "(none)" && -n "$installed" && "$installed" != "$candidate" ]]; then
    if ask_yes_no "Newer Alloy is available (${candidate}). Upgrade now?" "y"; then
      install_or_upgrade_alloy_apt
    else
      info "Keeping current Alloy version."
    fi
  else
    info "Alloy is up to date (or no candidate available)."
  fi
}

detect_alloy_user() { id alloy >/dev/null 2>&1 && echo alloy || echo ""; }

NEED_RESTART=0

ensure_group_membership() {
  local user="$1" group="$2"
  [[ -z "$user" || -z "$group" ]] && return 0
  if getent group "$group" >/dev/null 2>&1; then
    if id -nG "$user" | tr ' ' '\n' | grep -qx "$group"; then
      info "User '$user' already in group '$group'."
    else
      info "Adding user '$user' to group '$group'..."
      usermod -aG "$group" "$user"
      NEED_RESTART=1
    fi
  else
    warn "Group '$group' not found (skipping)."
  fi
}

# =========================
# Packs
# =========================
discover_packs() {
  [[ -d "$PACKS_DIR" ]] || err "packs directory not found: $PACKS_DIR"
  mapfile -t PACK_DIRS < <(find "$PACKS_DIR" -mindepth 1 -maxdepth 1 -type d | sort)
  [[ "${#PACK_DIRS[@]}" -gt 0 ]] || err "No packs found in $PACKS_DIR"
}

compute_default_selection_numbers() {
  local -a ids=()
  local -a default_nums=()
  local i

  [[ -n "${LAST_SELECTED_PACK_IDS:-}" ]] || { echo ""; return 0; }
  IFS=' ' read -r -a ids <<< "${LAST_SELECTED_PACK_IDS}"

  for i in "${!MENU_IDS[@]}"; do
    for wanted in "${ids[@]}"; do
      if [[ "${MENU_IDS[$i]}" == "$wanted" ]]; then
        default_nums+=("$((i+1))")
      fi
    done
  done

  echo "${default_nums[*]:-}"
}

was_enabled_last_time() {
  local pid="$1"
  [[ -n "${LAST_SELECTED_PACK_IDS:-}" ]] || return 1
  for x in ${LAST_SELECTED_PACK_IDS}; do
    [[ "$x" == "$pid" ]] && return 0
  done
  return 1
}

validate_signals_value() {
  local s="$1"
  s="$(echo "$s" | trim)"
  case "$s" in
    metrics|logs|none|metrics,logs|logs,metrics) return 0 ;;
    *) return 1 ;;
  esac
}

print_menu_and_select() {
  local -n out_selected_dirs=$1
  local -n out_selected_ids=$2

  echo
  echo "Available collection packs:"
  echo

  MENU_DIRS=()
  MENU_IDS=()

  local idx=1
  for d in "${PACK_DIRS[@]}"; do
    local conf="${d}/pack.conf"
    local tmpl="${d}/config.alloy.tmpl"
    [[ -f "$conf" ]] || { warn "Skipping (missing pack.conf): $d"; continue; }
    [[ -f "$tmpl" ]] || { warn "Skipping (missing config.alloy.tmpl): $d"; continue; }

    load_pack_conf "$conf"
    if ! validate_signals_value "$signals"; then
      warn "Skipping pack with invalid signals='$signals': $conf"
      continue
    fi

    MENU_DIRS+=("$d")
    MENU_IDS+=("$id")

    local mark="[ ]"
    if was_enabled_last_time "$id"; then
      mark="[x]"
    fi

    printf "  %2d) %s %s  [%s]\n" "$idx" "$mark" "$title" "$signals"
    idx=$((idx+1))
  done

  [[ "${#MENU_DIRS[@]}" -gt 0 ]] || err "No valid packs found."

  echo
  if [[ -n "${LAST_SELECTED_PACK_IDS:-}" ]]; then
    echo "Previously enabled packs: ${LAST_SELECTED_PACK_IDS}"
    echo
  fi

  local default_sel
  default_sel="$(compute_default_selection_numbers)"
  [[ -n "$default_sel" ]] || default_sel="1"

  local selection
  selection="$(ask_input "Select packs by number (space-separated)" "$default_sel")"

  local -a chosen_dirs=()
  local -a chosen_ids=()
  for s in $selection; do
    if [[ "$s" =~ ^[0-9]+$ ]] && (( s >= 1 && s <= ${#MENU_DIRS[@]} )); then
      chosen_dirs+=("${MENU_DIRS[$((s-1))]}")
      chosen_ids+=("${MENU_IDS[$((s-1))]}")
    else
      warn "Ignoring invalid selection: $s"
    fi
  done

  [[ "${#chosen_dirs[@]}" -gt 0 ]] || err "No valid packs selected."
  out_selected_dirs=("${chosen_dirs[@]}")
  out_selected_ids=("${chosen_ids[@]}")
}

list_available_pack_ids() {
  local -a ids=()
  for d in "${PACK_DIRS[@]}"; do
    local conf="${d}/pack.conf"
    [[ -f "$conf" ]] || continue
    load_pack_conf "$conf"
    validate_signals_value "$signals" || continue
    ids+=("$id")
  done
  echo "${ids[*]}"
}

select_packs_noninteractive() {
  local -n out_selected_dirs=$1
  local -n out_selected_ids=$2
  local list="$3"

  list="${list//,/ }"
  list="$(echo "$list" | trim)"
  [[ -n "$list" ]] || err "No packs specified. Use --packs or ensure state has LAST_SELECTED_PACK_IDS."

  local -a chosen_dirs=()
  local -a chosen_ids=()
  local wanted found d conf

  for wanted in $list; do
    found=""
    for d in "${PACK_DIRS[@]}"; do
      conf="${d}/pack.conf"
      [[ -f "$conf" ]] || continue
      load_pack_conf "$conf"
      validate_signals_value "$signals" || continue
      if [[ "$id" == "$wanted" ]]; then
        found="$d"
        break
      fi
    done
    [[ -n "$found" ]] || err "Unknown pack id '$wanted'. Available: $(list_available_pack_ids)"
    chosen_dirs+=("$found")
    chosen_ids+=("$wanted")
  done

  [[ "${#chosen_dirs[@]}" -gt 0 ]] || err "No valid packs selected."
  out_selected_dirs=("${chosen_dirs[@]}")
  out_selected_ids=("${chosen_ids[@]}")
}

# =========================
# Alloy config validation
# =========================
alloy_validate_file() {
  local path="$1"
  if ! has_cmd alloy; then
    warn "alloy command not found; skipping validate"
    return 0
  fi

  local args=()
  args+=(--stability.level="$STABILITY_LEVEL")

  if [[ "${COMMUNITY_COMPONENTS}" == "true" ]]; then
    args+=(--feature.community-components.enabled=true)
  fi

  alloy validate "${args[@]}" "$path"
}

# =========================
# Main
# =========================
main() {
  need_root
  info "Starting alloy-bootstrap setup (rerunnable) ..."

  [[ -d "$SINKS_DIR" ]] || err "sinks directory not found: $SINKS_DIR"

  load_state
  maybe_install_or_upgrade_alloy
  ensure_envsubst
  discover_packs

  local -a selected_dirs=()
  local -a selected_ids=()

  if [[ "${NONINTERACTIVE}" -eq 1 ]]; then
    if [[ -z "${PACKS_ARG}" && -n "${LAST_SELECTED_PACK_IDS:-}" ]]; then
      PACKS_ARG="${LAST_SELECTED_PACK_IDS}"
    fi
    select_packs_noninteractive selected_dirs selected_ids "${PACKS_ARG}"
  else
    print_menu_and_select selected_dirs selected_ids
  fi

  local need_metrics=0 need_logs=0
  local -a required_groups=()
  local -a required_vars=()
  local -a required_cmds=()

  for d in "${selected_dirs[@]}"; do
    load_pack_conf "${d}/pack.conf"

    [[ -n "$requires_cmd" ]] && required_cmds+=("$requires_cmd")
    [[ -n "$requires_group" ]] && required_groups+=("$requires_group")

    IFS=',' read -r -a sigs <<< "$signals"
    for sig in "${sigs[@]}"; do
      sig="$(echo "$sig" | trim)"
      [[ "$sig" == "metrics" ]] && need_metrics=1
      [[ "$sig" == "logs" ]] && need_logs=1
    done

    if [[ -n "$vars" ]]; then
      IFS=',' read -r -a vlist <<< "$vars"
      for v in "${vlist[@]}"; do
        v="$(echo "$v" | trim)"
        [[ -n "$v" ]] && required_vars+=("$v")
      done
    fi
  done

  mapfile -t required_groups < <(printf "%s\n" "${required_groups[@]}" | dedup_lines || true)
  mapfile -t required_vars   < <(printf "%s\n" "${required_vars[@]}" | dedup_lines || true)
  mapfile -t required_cmds   < <(printf "%s\n" "${required_cmds[@]}" | dedup_lines || true)

  for c in "${required_cmds[@]}"; do
    [[ -n "$c" ]] || continue
    if ! has_cmd "$c"; then
      warn "Selected pack expects command '$c' but it isn't installed."
    fi
  done

  if [[ "$need_metrics" == "1" ]]; then
    local default_prom="${LAST_PROM_BASE_URL:-}"
    local raw base

    if [[ "${NONINTERACTIVE}" -eq 1 ]]; then
      raw="${PROM_BASE_URL_ARG:-$default_prom}"
      [[ -n "$raw" ]] || err "Metrics packs selected but no Prometheus base provided. Use --prom-base-url or ensure state has LAST_PROM_BASE_URL."
      base="$(normalize_base_url "$raw")" || err "Invalid Prometheus base: $raw"
      validate_base_url "$base" || err "Invalid Prometheus base: $base (expected http(s)://host:port)"
      PROM_REMOTE_WRITE_URL="$(join_url_path "$base" "$PROM_REMOTE_WRITE_PATH")"
      export PROM_REMOTE_WRITE_URL
      LAST_PROM_BASE_URL="$base"
      info "Using Prometheus/VictoriaMetrics base: $base"
    else
      while true; do
        raw="$(ask_nonempty "Prometheus/VictoriaMetrics base (previous: ${default_prom:-none}) — enter http(s)://host:port or host:port" "$default_prom")"
        if base="$(normalize_base_url "$raw")" && validate_base_url "$base"; then
          PROM_REMOTE_WRITE_URL="$(join_url_path "$base" "$PROM_REMOTE_WRITE_PATH")"
          export PROM_REMOTE_WRITE_URL
          LAST_PROM_BASE_URL="$base"
          info "Using Prometheus/VictoriaMetrics base: $base"
          break
        fi
        echo "Example: http://PROMTHUES_IP_OR_DNS:9090"
      done
    fi
  fi

  if [[ "$need_logs" == "1" ]]; then
    local default_loki="${LAST_LOKI_BASE_URL:-}"
    local raw base

    if [[ "${NONINTERACTIVE}" -eq 1 ]]; then
      raw="${LOKI_BASE_URL_ARG:-$default_loki}"
      [[ -n "$raw" ]] || err "Logs packs selected but no Loki base provided. Use --loki-base-url or ensure state has LAST_LOKI_BASE_URL."
      base="$(normalize_base_url "$raw")" || err "Invalid Loki base: $raw"
      validate_base_url "$base" || err "Invalid Loki base: $base (expected http(s)://host:port)"
      LOKI_PUSH_URL="$(join_url_path "$base" "$LOKI_PUSH_PATH")"
      export LOKI_PUSH_URL
      LAST_LOKI_BASE_URL="$base"
      info "Using Loki base: $base"
    else
      while true; do
        raw="$(ask_nonempty "Loki base (previous: ${default_loki:-none}) — enter http(s)://host:port or host:port" "$default_loki")"
        if base="$(normalize_base_url "$raw")" && validate_base_url "$base"; then
          LOKI_PUSH_URL="$(join_url_path "$base" "$LOKI_PUSH_PATH")"
          export LOKI_PUSH_URL
          LAST_LOKI_BASE_URL="$base"
          info "Using Loki base: $base"
          break
        fi
        echo "Example: http://LOKI_IP_OR_DNS:3400"
      done
    fi
  fi

  if [[ "${#required_vars[@]}" -gt 0 ]]; then
    echo
    info "Pack-specific settings:"
    for spec in "${required_vars[@]}"; do
      [[ -n "$spec" ]] || continue
      IFS=':' read -r varname prompt defval <<< "$spec"
      if [[ -z "${varname:-}" || -z "${prompt:-}" ]]; then
        warn "Skipping invalid var spec: $spec"
        continue
      fi

      local val=""
      if [[ -n "${!varname:-}" ]]; then
        val="${!varname}"
      elif [[ -n "${CLI_VARS[$varname]+x}" ]]; then
        val="${CLI_VARS[$varname]}"
      elif [[ "${NONINTERACTIVE}" -eq 1 ]]; then
        if [[ -n "${defval:-}" ]]; then
          val="${defval}"
        else
          err "Missing required pack var '${varname}'. Provide --var ${varname}=... or set env var ${varname}."
        fi
      else
        val="$(ask_input "$prompt" "${defval:-}")"
      fi

      export "${varname}=${val}"
      info "Using ${varname}=${val}"
    done
  fi

  local CUSTOM_ARGS=""
  if [[ "${NONINTERACTIVE}" -eq 1 ]]; then
    if [[ "${NO_UI}" -eq 1 ]]; then
      CUSTOM_ARGS=""
      LAST_UI_LISTEN_ADDR=""
    elif [[ -n "${UI_LISTEN_ADDR_ARG}" ]]; then
      validate_listen_addr "${UI_LISTEN_ADDR_ARG}" || err "Invalid --ui-listen-addr (expected host:port): ${UI_LISTEN_ADDR_ARG}"
      CUSTOM_ARGS="--server.http.listen-addr=${UI_LISTEN_ADDR_ARG}"
      LAST_UI_LISTEN_ADDR="${UI_LISTEN_ADDR_ARG}"
      info "Using Alloy UI listen addr: ${UI_LISTEN_ADDR_ARG}"
      if [[ "${UI_LISTEN_ADDR_ARG}" == 0.0.0.0:* || "${UI_LISTEN_ADDR_ARG}" == ::* ]]; then
        warn "Alloy UI bound to a public interface (${UI_LISTEN_ADDR_ARG}). Ensure firewalling or bind to 127.0.0.1."
      fi
    else
      CUSTOM_ARGS=""
      LAST_UI_LISTEN_ADDR=""
    fi
  else
    if ask_yes_no "Expose Alloy HTTP UI on network (sets --server.http.listen-addr)?" "n"; then
      local default_ui="${LAST_UI_LISTEN_ADDR:-127.0.0.1:12345}"
      local addr
      while true; do
        addr="$(ask_input "Listen address (host:port)" "$default_ui")"
        if validate_listen_addr "$addr"; then
          CUSTOM_ARGS="--server.http.listen-addr=${addr}"
          LAST_UI_LISTEN_ADDR="$addr"
          info "Using Alloy UI listen addr: $addr"
          if [[ "$addr" == 0.0.0.0:* || "$addr" == ::* ]]; then
            warn "Alloy UI bound to a public interface ($addr). Ensure firewalling or bind to 127.0.0.1."
          fi
          break
        fi
        echo "Example: 127.0.0.1:12345"
      done
    else
      LAST_UI_LISTEN_ADDR=""
    fi
  fi

  mkdir -p "$CFG_DIR"

  # If CUSTOM_ARGS changes, we must restart Alloy (reload won't apply CLI args)
  local OLD_CUSTOM_ARGS
  OLD_CUSTOM_ARGS="$(read_current_custom_args)"

  # Write /etc/default/alloy
  local tmp_env
  tmp_env="$(mktemp)"
  backup_file "$ENV_FILE"
  cat > "$tmp_env" <<EOF
# Managed by alloy-bootstrap setup.sh
CONFIG_FILE="${CFG_FILE}"
CUSTOM_ARGS="${CUSTOM_ARGS}"
EOF
  install -m 0644 "$tmp_env" "$ENV_FILE"
  rm -f "$tmp_env"
  info "Wrote $ENV_FILE"

  if [[ "$OLD_CUSTOM_ARGS" != "$CUSTOM_ARGS" ]]; then
    info "CUSTOM_ARGS changed; Alloy must restart to apply new command-line args."
    NEED_RESTART=1
  fi

  # Build ENVSUBST allow-list based on chosen sinks + pack vars
  local allowed_vars=""
  if [[ "$need_metrics" == "1" ]]; then
    allowed_vars+=' ${PROM_REMOTE_WRITE_URL}'
  fi
  if [[ "$need_logs" == "1" ]]; then
    allowed_vars+=' ${LOKI_PUSH_URL}'
  fi

  if [[ "${#required_vars[@]}" -gt 0 ]]; then
    for spec in "${required_vars[@]}"; do
      IFS=':' read -r varname _prompt _defval <<< "$spec"
      [[ -n "${varname:-}" ]] && allowed_vars+=" \${${varname}}"
    done
  fi
  ENVSUBST_VARS="$(echo "$allowed_vars" | trim)"
  export ENVSUBST_VARS

  # Render config to a temp file, fmt+validate it, then atomically install it
  local tmp_cfg
  tmp_cfg="$(mktemp)"
  {
    echo "// Managed by alloy-bootstrap setup.sh"
    echo

    if [[ "$need_metrics" == "1" ]]; then
      render_template "${SINKS_DIR}/prometheus_remote_write.alloy.tmpl"
      echo
    fi

    if [[ "$need_logs" == "1" ]]; then
      render_template "${SINKS_DIR}/loki_write.alloy.tmpl"
      echo
    fi

    for d in "${selected_dirs[@]}"; do
      load_pack_conf "${d}/pack.conf"
      echo "// ---- pack: ${id} (${title}) ----"
      render_template "${d}/config.alloy.tmpl"
      echo
    done
  } > "$tmp_cfg"

  if has_cmd alloy; then
    alloy fmt --write "$tmp_cfg"
    alloy_validate_file "$tmp_cfg"
  else
    warn "alloy not found; skipping fmt/validate"
  fi

  backup_file "$CFG_FILE"
  install -m 0644 "$tmp_cfg" "$CFG_FILE"
  rm -f "$tmp_cfg"
  info "Installed validated config to $CFG_FILE"

  # Permissions/groups (may require restart)
  local alloy_user
  alloy_user="$(detect_alloy_user)"
  if [[ -n "$alloy_user" ]]; then
    for g in "${required_groups[@]}"; do
      [[ -n "$g" ]] && ensure_group_membership "$alloy_user" "$g"
    done
    if [[ "$need_logs" == "1" ]]; then
      ensure_group_membership "$alloy_user" "systemd-journal"
      ensure_group_membership "$alloy_user" "adm"
    fi
  else
    warn "User 'alloy' not found; skipping group membership updates."
  fi

  # ---- Run pack post-install hooks ----
  for d in "${selected_dirs[@]}"; do
    local hook="${d}/post-install.sh"
    if [[ -x "$hook" ]]; then
      info "Running post-install hook for $(basename "$d")..."
      if bash "$hook"; then
        info "Post-install hook completed: $(basename "$d")"
      else
        warn "Post-install hook failed: $(basename "$d") (continuing anyway)"
      fi
    fi
  done

  systemctl enable --now alloy.service >/dev/null 2>&1 || true

  if (( NEED_RESTART )); then
    info "Restarting Alloy (required to apply group or argument changes)..."
    systemctl restart alloy
    info "Restarted Alloy."
  else
    if systemctl reload alloy >/dev/null 2>&1; then
      info "Reloaded Alloy."
    else
      warn "Reload failed; restarting Alloy..."
      systemctl restart alloy
      info "Restarted Alloy."
    fi
  fi

  # Save "last run" for next time
  LAST_SELECTED_PACK_IDS="${selected_ids[*]}"
  save_state

  info "Done. Run again anytime after git pull or when adding packs."
  if [[ "$need_metrics" == "1" ]]; then
    echo "  Prom remote_write: ${PROM_REMOTE_WRITE_URL}"
  fi
  if [[ "$need_logs" == "1" ]]; then
    echo "  Loki push:         ${LOKI_PUSH_URL}"
  fi
  if [[ -n "${LAST_UI_LISTEN_ADDR:-}" ]]; then
    echo "  Alloy UI listen:   ${LAST_UI_LISTEN_ADDR}"
  fi
}

main
