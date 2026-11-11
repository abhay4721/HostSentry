#!/usr/bin/env bash
set -euo pipefail

if [[ ${EUID} -ne 0 ]]; then
  echo "Run this uninstaller as root (for example: sudo ./scripts/uninstall-agent.sh)." >&2
  exit 1
fi

systemctl disable --now hostsentry-agent.service 2>/dev/null || true
rm -f /etc/systemd/system/hostsentry-agent.service /usr/local/bin/hostsentry-agent
systemctl daemon-reload
systemctl reset-failed hostsentry-agent.service 2>/dev/null || true
echo "HostSentry service and binary removed. Configuration and reports remain in /etc/hostsentry and /var/lib/hostsentry."
