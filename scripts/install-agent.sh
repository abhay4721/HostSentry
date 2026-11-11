#!/usr/bin/env bash
set -euo pipefail

if [[ ${EUID} -ne 0 ]]; then
  echo "Run this installer as root (for example: sudo ./scripts/install-agent.sh)." >&2
  exit 1
fi

repo_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
binary=${repo_dir}/bin/hostsentry-agent
if [[ ! -x ${binary} ]]; then
  echo "${binary} is missing. Build it first with: make build-agent" >&2
  exit 1
fi

if ! command -v systemctl >/dev/null 2>&1; then
  echo "systemctl is required; this installer supports systemd hosts." >&2
  exit 1
fi

if ! getent group hostsentry >/dev/null; then
  groupadd --system hostsentry
fi
if ! id hostsentry >/dev/null 2>&1; then
  useradd --system --gid hostsentry --home-dir /var/lib/hostsentry --create-home --shell /usr/bin/nologin hostsentry
fi

install -d -o root -g hostsentry -m 0750 /etc/hostsentry
install -d -o hostsentry -g hostsentry -m 0750 /var/lib/hostsentry
install -o root -g root -m 0755 "${binary}" /usr/local/bin/hostsentry-agent
if [[ ! -e /etc/hostsentry/hostsentry.yaml ]]; then
  install -o root -g hostsentry -m 0640 "${repo_dir}/examples/hostsentry.yaml" /etc/hostsentry/hostsentry.yaml
fi
install -o root -g root -m 0644 "${repo_dir}/deploy/hostsentry-agent.service" /etc/systemd/system/hostsentry-agent.service

systemctl daemon-reload
systemctl enable --now hostsentry-agent.service
systemctl --no-pager --full status hostsentry-agent.service
