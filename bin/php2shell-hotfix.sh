#!/usr/bin/env bash
# php2shell-hotfix — detect PHP2Shell and apply the vendor's temporary mitigations.
# CVE-2026-109618 (GHSA-w8hw-w9fx-j79w) and CVE-2026-109619 (GHSA-6wmf-4rv5-p3rp).
#
# This does not patch the PHP engine. The only complete fix is a patched binary:
#   PHP 8.2.35, 8.3.36, 8.4.27, or 8.5.12 (or a newer release on that branch).
# Configuration changes below are the partial mitigations published by the PHP
# project. They are not a substitute for upgrading.
#
# This script never downloads third-party binaries and contains no exploit code.
set -euo pipefail

MARKER="php2shell-hotfix:CVE-2026-109618:CVE-2026-109619"
INI_NAME="99-php2shell-mitigation.ini"
APPLY=0
RESTART=0
MODE="status"
declare -a EXTRA_BINS=()

usage() {
  cat <<'EOF'
Usage: php2shell-hotfix.sh <status|mitigate|revert|upgrade> [options]

  status     Show every PHP binary and whether it is below the patched release.
  mitigate   Install the official temporary php.ini drop-in (needs --apply).
  revert     Remove only the drop-in this tool wrote.
  upgrade    Upgrade already-installed distro PHP packages (needs --apply).

Options:
  --apply     Actually change the system. Without it, commands only print a plan.
  --restart   After --apply mitigate, reload php-fpm and apache if systemd is present.
  --php PATH  Also inspect this binary (repeatable).

The drop-in sets:
  session.upload_progress.enabled = 0
  memory_limit = -1
  fatal_error_backtraces = 0     (only when that binary is PHP 8.5)

memory_limit=-1 removes PHP's per-request cap. Pair it with a cgroup/container
memory limit. Do not use RLIMIT_AS or RLIMIT_DATA — those take the vulnerable path.
EOF
}

die() { printf 'error: %s\n' "$*" >&2; exit 1; }

classify_version() {
  local ver="$1" major minor patch branch floor
  if [[ ! "$ver" =~ ^([0-9]+)\.([0-9]+)\.([0-9]+) ]]; then
    printf 'unknown'
    return
  fi
  major="${BASH_REMATCH[1]}"
  minor="${BASH_REMATCH[2]}"
  patch="${BASH_REMATCH[3]}"
  if (( major > 8 || (major == 8 && minor > 5) )); then
    printf 'unknown'
    return
  fi
  branch="${major}.${minor}"
  case "$branch" in
    8.2) floor=35 ;;
    8.3) floor=36 ;;
    8.4) floor=27 ;;
    8.5) floor=12 ;;
    *) printf 'eol'; return ;;
  esac
  if (( patch >= floor )); then
    printf 'patched'
  else
    printf 'vulnerable'
  fi
}

fixed_target_for() {
  local ver="$1" major minor
  [[ "$ver" =~ ^([0-9]+)\.([0-9]+)\. ]] || return 0
  major="${BASH_REMATCH[1]}"
  minor="${BASH_REMATCH[2]}"
  case "${major}.${minor}" in
    8.2) printf '8.2.35' ;;
    8.3) printf '8.3.36' ;;
    8.4) printf '8.4.27' ;;
    8.5) printf '8.5.12' ;;
    *) printf '8.2.35 or newer supported branch' ;;
  esac
}

php_version_of() {
  local bin="$1" ver=""
  if [[ -x "$bin" ]]; then
    ver=$("$bin" -r 'echo PHP_VERSION;' 2>/dev/null || true)
    if [[ ! "$ver" =~ ^[0-9]+\.[0-9]+\.[0-9]+ ]]; then
      ver=$("$bin" -v 2>/dev/null | sed -n 's/.*PHP \([0-9][0-9]*\.[0-9][0-9]*\.[0-9][0-9]*\).*/\1/p' | head -n 1 || true)
    fi
  fi
  printf '%s' "$ver"
}

ini_scan_dir() {
  local bin="$1" line="" first=""
  line=$("$bin" --ini 2>/dev/null | sed -n 's/^Scan for additional \.ini files in:[[:space:]]*//p' | head -n 1 || true)
  line="${line%"${line##*[![:space:]]}"}"
  if [[ -n "$line" && "$line" != "(none)" ]]; then
    printf '%s' "$line"
    return
  fi
  line=$("$bin" --ini 2>/dev/null | sed -n 's/^Additional \.ini files parsed:[[:space:]]*//p' | head -n 1 || true)
  if [[ -n "$line" && "$line" != "(none)" ]]; then
    first="${line%%,*}"
    first="${first#"${first%%[![:space:]]*}"}"
    first="${first%"${first##*[![:space:]]}"}"
    if [[ -n "$first" && "$first" == */* ]]; then
      dirname "$first"
    fi
  fi
}

discover_bins() {
  local b
  shopt -s nullglob
  for b in \
    /usr/bin/php /usr/bin/php[0-9].[0-9] /usr/bin/php[0-9][0-9] \
    /usr/sbin/php-fpm /usr/sbin/php-fpm[0-9].[0-9] \
    /usr/local/bin/php /usr/local/sbin/php-fpm
  do
    [[ -x "$b" && -f "$b" ]] && printf '%s\n' "$b"
  done
  if command -v php >/dev/null 2>&1; then
    command -v php
  fi
  if command -v php-fpm >/dev/null 2>&1; then
    command -v php-fpm
  fi
  for b in "${EXTRA_BINS[@]+"${EXTRA_BINS[@]}"}"; do
    printf '%s\n' "$b"
  done
  shopt -u nullglob
}

discover_ini_dirs() {
  local b dir bins_text
  bins_text=$(discover_bins | awk '!seen[$0]++' || true)
  while IFS= read -r b; do
    [[ -n "$b" ]] || continue
    dir=$(ini_scan_dir "$b" || true)
    [[ -n "$dir" ]] && printf '%s\n' "$dir"
  done <<EOF
$bins_text
EOF
  shopt -s nullglob
  for dir in /etc/php/*/*/conf.d /etc/php.d /etc/php*/conf.d /usr/local/etc/php/conf.d /opt/homebrew/etc/php/*/conf.d; do
    [[ -d "$dir" ]] && printf '%s\n' "$dir"
  done
  shopt -u nullglob
}

ini_body_for() {
  local ver="$1" verdict
  verdict=$(classify_version "$ver")
  cat <<EOF
; ${MARKER}
; Temporary, partial mitigation. NOT a complete fix.
; Upgrade target for this binary: $(fixed_target_for "$ver")
; Remove with: php2shell-hotfix.sh revert --apply
; Do not set RLIMIT_AS or RLIMIT_DATA.
session.upload_progress.enabled = 0
memory_limit = -1
EOF
  if [[ "$ver" =~ ^8\.5\. ]]; then
    printf 'fatal_error_backtraces = 0\n'
  fi
  if [[ "$verdict" == "patched" ]]; then
    printf '; This binary already reports a patched version. Prefer revert after workers restart on the new binary.\n'
  fi
}

cmd_status() {
  local found=0 bin ver verdict target bins_text
  printf '%-32s %-12s %-12s %s\n' "BINARY" "VERSION" "STATUS" "UPGRADE TO"
  bins_text=$(discover_bins | awk '!seen[$0]++' || true)
  while IFS= read -r bin; do
    [[ -n "$bin" ]] || continue
    found=1
    ver=$(php_version_of "$bin")
    if [[ -z "$ver" ]]; then
      printf '%-32s %-12s %-12s %s\n' "$bin" "?" "unreadable" "-"
      continue
    fi
    verdict=$(classify_version "$ver")
    target=$(fixed_target_for "$ver")
    printf '%-32s %-12s %-12s %s\n' "$bin" "$ver" "$verdict" "$target"
  done <<EOF
$bins_text
EOF
  if [[ "$found" -eq 0 ]]; then
    printf 'No PHP binary found. Pass --php /path/to/php\n'
    return 1
  fi
  cat <<'EOF'

status meanings:
  patched     This binary is at or above the 21 Oct 2026 security release.
  vulnerable  Supported branch, older than the patched release. Upgrade.
  eol         PHP 8.1 and older have no supported point release. Move to 8.2.35+
              or build the published backport branch (see README).
  unknown     Newer than PHP 8.5, or the version could not be classified.
              Confirm the vendor advisory before treating it as safe.

Configuration mitigations are partial. Updating the binary is the only complete fix.
EOF
}

write_dropin() {
  local dir="$1" ver="$2" path
  path="${dir%/}/${INI_NAME}"
  if [[ "$APPLY" -eq 0 ]]; then
    printf 'plan: write %s\n' "$path"
    return 0
  fi
  if [[ ! -d "$dir" ]]; then
    printf 'skip: %s does not exist\n' "$dir" >&2
    return 0
  fi
  if [[ ! -w "$dir" ]]; then
    printf 'skip: %s is not writable (re-run with sudo)\n' "$dir" >&2
    return 1
  fi
  ini_body_for "$ver" > "$path"
  chmod 644 "$path"
  printf 'wrote %s\n' "$path"
}

representative_version() {
  local bin ver bins_text
  bins_text=$(discover_bins | awk '!seen[$0]++' || true)
  while IFS= read -r bin; do
    ver=$(php_version_of "$bin")
    if [[ -n "$ver" ]]; then
      printf '%s' "$ver"
      return
    fi
  done <<EOF
$bins_text
EOF
  printf '0.0.0'
}

cmd_mitigate() {
  local dir ver wrote=0 failed=0 dirs_text
  ver=$(representative_version)
  if [[ "$APPLY" -eq 0 ]]; then
    printf 'Dry run. Pass --apply to write files. Detected PHP %s (%s).\n' "$ver" "$(classify_version "$ver")"
    printf 'memory_limit=-1 disables the per-request memory cap. Use a cgroup limit instead of RLIMIT_AS/RLIMIT_DATA.\n\n'
  fi
  dirs_text=$(discover_ini_dirs | awk '!seen[$0]++' || true)
  while IFS= read -r dir; do
    [[ -n "$dir" ]] || continue
    ver=$(version_for_dir "$dir")
    if write_dropin "$dir" "$ver"; then
      wrote=1
    else
      failed=1
    fi
  done <<EOF
$dirs_text
EOF
  if [[ "$wrote" -eq 0 && "$APPLY" -eq 1 ]]; then
    printf 'No ini scan directory found. Drop this file in manually:\n\n' >&2
    ini_body_for "$ver" >&2
    exit 1
  fi
  if [[ "$failed" -ne 0 ]]; then
    exit 1
  fi
  if [[ "$APPLY" -eq 1 ]]; then
    printf '\nRestart every PHP worker so the drop-in is loaded. ini_set() and .user.ini are too late.\n'
    if [[ "$RESTART" -eq 1 ]]; then
      restart_services || true
    else
      printf 'Re-run with --apply --restart, or reload php-fpm and apache yourself.\n'
    fi
  fi
}

version_for_dir() {
  local dir="$1" branch="" cand ver=""
  local -a cands=()
  if ((${#EXTRA_BINS[@]})); then
    cands+=("${EXTRA_BINS[@]}")
  fi
  if [[ "$dir" =~ php@?/?([0-9]+\.[0-9]+) ]]; then
    branch="${BASH_REMATCH[1]}"
    cands+=("/usr/bin/php${branch}" "/usr/sbin/php-fpm${branch}" "/usr/local/bin/php${branch}" "/opt/homebrew/opt/php@${branch}/bin/php")
    for cand in "${cands[@]}"; do
      [[ -n "$cand" && -x "$cand" ]] || continue
      ver=$(php_version_of "$cand")
      if [[ "$ver" == "${branch}."* ]]; then
        printf '%s' "$ver"
        return
      fi
    done
  fi
  representative_version
}

restart_services() {
  command -v systemctl >/dev/null 2>&1 || { printf 'systemctl not found; restart PHP yourself.\n'; return 0; }
  local unit units_text
  units_text=$(systemctl list-units --type=service --all --no-legend 'php*-fpm.service' 'apache2.service' 'httpd.service' 2>/dev/null | awk '{print $1}' || true)
  while IFS= read -r unit; do
    [[ -n "$unit" ]] || continue
    if systemctl reload "$unit"; then
      printf 'reloaded %s\n' "$unit"
    elif systemctl restart "$unit"; then
      printf 'restarted %s\n' "$unit"
    else
      printf 'could not restart %s\n' "$unit" >&2
    fi
  done <<EOF
$units_text
EOF
}

cmd_revert() {
  local dir path dirs_text
  dirs_text=$(discover_ini_dirs | awk '!seen[$0]++' || true)
  while IFS= read -r dir; do
    [[ -n "$dir" ]] || continue
    path="${dir%/}/${INI_NAME}"
    if [[ -f "$path" ]] && grep -q "$MARKER" "$path"; then
      if [[ "$APPLY" -eq 0 ]]; then
        printf 'plan: remove %s\n' "$path"
      else
        rm -f "$path"
        printf 'removed %s\n' "$path"
      fi
    fi
  done <<EOF
$dirs_text
EOF
  if [[ "$APPLY" -eq 0 ]]; then
    printf 'Dry run. Pass --apply to delete the drop-in.\n'
  else
    printf 'Restart PHP workers after revert.\n'
    [[ "$RESTART" -eq 1 ]] && restart_services || true
  fi
}

upgrade_plan() {
  local id=""
  if [[ -r /etc/os-release ]]; then
    # shellcheck disable=SC1091
    id=$(. /etc/os-release && printf '%s' "${ID:-}")
  fi
  case "$id" in
    ubuntu|debian)
      cat <<'EOF'
apt-get update
pkgs=$(dpkg-query -W -f='${Package}\n' 'php*' 2>/dev/null || true)
test -n "$pkgs" || { echo "no dpkg php packages"; exit 1; }
DEBIAN_FRONTEND=noninteractive apt-get install --only-upgrade -y $pkgs
EOF
      ;;
    fedora|rhel|centos|almalinux|rocky|amzn)
      printf '%s\n' "dnf -y upgrade 'php*' || yum -y upgrade 'php*'"
      ;;
    alpine)
      printf '%s\n' "apk update && apk upgrade php php-fpm php-cli"
      ;;
    *)
      printf '%s\n' "# Unrecognized OS (${id:-unknown}). Upgrade with your vendor's patched PHP package."
      ;;
  esac
  cat <<'EOF'
# Docker / Kubernetes: rebuild the image on a patched tag (php:8.2.35, php:8.3.36,
# php:8.4.27, php:8.5.12, or newer) and roll the workload. Restarting keeps the old binary.
# Source and Windows builds: https://www.php.net/downloads.php
# EOL backports (7.4, 8.0, 8.1), official branches only:
#   https://github.com/php/php-src/tree/PHP-7.4-CVE-2026-109618-109619
#   https://github.com/php/php-src/tree/PHP-8.0-CVE-2026-109618-109619
#   https://github.com/php/php-src/tree/PHP-8.1-CVE-2026-109618-109619
EOF
}

cmd_upgrade() {
  if [[ "$APPLY" -eq 0 ]]; then
    printf 'Dry run. This only upgrades PHP packages already installed by the OS.\n'
    printf 'It will not add PPAs, third-party repos, or compile PHP.\n\n'
    upgrade_plan
    printf '\nPass --apply as root to run the plan, then re-run status.\n'
    return 0
  fi
  [[ "$(id -u)" -eq 0 ]] || die "upgrade --apply must run as root"
  local id=""
  if [[ -r /etc/os-release ]]; then
    id=$(. /etc/os-release && printf '%s' "${ID:-}")
  fi
  case "$id" in
    ubuntu|debian)
      apt-get update
      local pkgs
      pkgs=$(dpkg-query -W -f='${Package}\n' 'php*' 2>/dev/null || true)
      [[ -n "$pkgs" ]] || die "no php* packages installed via dpkg"
      # shellcheck disable=SC2086
      DEBIAN_FRONTEND=noninteractive apt-get install --only-upgrade -y $pkgs
      ;;
    fedora|rhel|centos|almalinux|rocky|amzn)
      if command -v dnf >/dev/null 2>&1; then
        dnf -y upgrade 'php*'
      elif command -v yum >/dev/null 2>&1; then
        yum -y upgrade 'php*'
      else
        die "neither dnf nor yum is installed"
      fi
      ;;
    alpine)
      apk update
      apk upgrade php php-fpm php-cli
      ;;
    *)
      die "no automatic upgrade for OS '${id:-unknown}'. See the printed plan without --apply."
      ;;
  esac
  printf '\nUpgrade command finished. Confirm the binary, then restart workers:\n'
  cmd_status || true
}

parse_args() {
  local arg
  [[ $# -gt 0 ]] || { usage; exit 1; }
  case "$1" in
    status|mitigate|revert|upgrade) MODE="$1"; shift ;;
    -h|--help|help) usage; exit 0 ;;
    *) die "unknown command: $1" ;;
  esac
  while [[ $# -gt 0 ]]; do
    arg="$1"
    case "$arg" in
      --apply) APPLY=1 ;;
      --restart) RESTART=1 ;;
      --php)
        shift
        [[ $# -gt 0 ]] || die "--php needs a path"
        EXTRA_BINS+=("$1")
        ;;
      -h|--help) usage; exit 0 ;;
      *) die "unknown option: $arg" ;;
    esac
    shift
  done
}

main() {
  parse_args "$@"
  case "$MODE" in
    status) cmd_status ;;
    mitigate) cmd_mitigate ;;
    revert) cmd_revert ;;
    upgrade) cmd_upgrade ;;
  esac
}

if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
  main "$@"
fi
