#!/usr/bin/env bash
# CI: system packages for building Patchbay on Ubuntu
# (GitHub's ubuntu runners). Tauri 2 needs WebKitGTK 4.1.
# The GStreamer plugins are bundled into the AppImage (bundleMediaFramework), so audio plays there.
#
# The Ubuntu mirrors sometimes stall instead of failing (a run once sat in apt for 45 minutes,
# normally ~40s). A mirror that trickles bytes also never trips apt's own network timeout, which
# only fires on silence. So each phase runs under a hard limit, every line of output is timestamped
# (to see which phase and package stalled), and a retry first switches to another mirror.
#
# Environment (all optional):
#   APT_ARCHIVES       Directory that keeps the downloaded .deb files between runs. The
#                      .github/actions/deps-ubuntu action caches it, so a warm run downloads nothing.
#   APT_UPDATE_LIMIT   Hard limit for `apt-get update` (default 90s).
#   APT_INSTALL_LIMIT  Hard limit for `apt-get install` (default 4m).
set -euo pipefail

update_limit=${APT_UPDATE_LIMIT:-90s}
install_limit=${APT_INSTALL_LIMIT:-4m}
archives=${APT_ARCHIVES:-}

apt=(sudo apt-get -o Acquire::Retries=3 -o Acquire::http::Timeout=20 -o Acquire::https::Timeout=20)
if [ -n "$archives" ]; then
  mkdir -p "$archives/partial"
  # Downloads as root: the sandbox user (_apt) cannot write to a directory the runner user owns.
  apt+=(-o "Dir::Cache::archives=$archives" -o APT::Sandbox::User=root)
fi

packages=(
  build-essential curl file patchelf pkg-config
  libwebkit2gtk-4.1-dev libgtk-3-dev libayatana-appindicator3-dev librsvg2-dev
  libssl-dev libdbus-1-dev libxdo-dev
  gstreamer1.0-plugins-base gstreamer1.0-plugins-good gstreamer1.0-plugins-ugly gstreamer1.0-libav
)

# Prefix each line with the time it arrived. The last line may lack a newline.
stamp() {
  local line
  while IFS= read -r line || [ -n "$line" ]; do
    printf '%(%H:%M:%S)T %s\n' -1 "$line"
  done
}

# run <label> <limit> <command...>: the command under a hard limit, output timestamped.
# `--kill-after` follows the TERM with a KILL, for an apt-get that ignores TERM.
run() {
  local label=$1 limit=$2 rc=0
  shift 2
  echo "deps-ubuntu: $label (limit $limit)"
  timeout --kill-after=15s "$limit" "$@" 2>&1 | stamp || rc=${PIPESTATUS[0]}
  if [ "$rc" -eq 124 ] || [ "$rc" -eq 137 ]; then
    echo "deps-ubuntu: $label hit the $limit limit and was stopped" >&2
  fi
  return "$rc"
}

# GitHub's Ubuntu images point apt at Azure's mirror, which is the one that stalls.
use_fallback_mirror() {
  local files=(/etc/apt/sources.list /etc/apt/sources.list.d/*)
  echo "deps-ubuntu: switching from azure.archive.ubuntu.com to archive.ubuntu.com"
  sudo sed -i 's#//azure\.archive\.ubuntu\.com/#//archive.ubuntu.com/#g' "${files[@]}" 2>/dev/null || true
}

# A killed install can leave dpkg half-way through a package; finish it before trying again.
recover() {
  run "dpkg --configure -a" 1m sudo dpkg --configure -a || true
}

finish() {
  if [ -n "$archives" ]; then
    # Leave only the .deb files for the cache step: the runner user reads them, and `partial` and
    # `lock` are root-owned scratch that would make the cache's tar fail.
    sudo rm -rf "$archives/partial" "$archives/lock"
    sudo chown -R "$(id -u):$(id -g)" "$archives"
  fi
}

for attempt in 1 2 3; do
  if [ "$attempt" -ge 2 ]; then
    use_fallback_mirror
    recover
  fi
  if run "apt-get update" "$update_limit" "${apt[@]}" update &&
    run "apt-get install" "$install_limit" "${apt[@]}" install -y --no-install-recommends "${packages[@]}"; then
    finish
    exit 0
  fi
  echo "deps-ubuntu: attempt $attempt failed or timed out" >&2
done
exit 1
