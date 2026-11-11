#!/usr/bin/env bash
set -euo pipefail

if [[ ${EUID} -ne 0 ]]; then
  echo "Run as root (for example: sudo ./scripts/connect-agent.sh arch-linux)." >&2
  exit 1
fi

repo_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
agent_id=${1:-}
server_url=${2:-https://localhost:8444}
if [[ ! ${agent_id} =~ ^[A-Za-z0-9_-]{1,128}$ ]]; then
  echo "Usage: $0 <agent-id> [https://server:8444]" >&2
  exit 2
fi
if [[ ! ${server_url} =~ ^https://[A-Za-z0-9.-]+(:[0-9]{1,5})?$ ]]; then
  echo "Server URL must be an HTTPS origin, such as https://localhost:8444." >&2
  exit 2
fi
if [[ ! -r ${repo_dir}/pki/ca.crt || ! -r ${repo_dir}/pki/agents/${agent_id}/agent.crt || ! -r ${repo_dir}/pki/agents/${agent_id}/agent.key ]]; then
  echo "CA or agent certificate is missing. Run setup-central.sh and issue-agent-cert.sh first." >&2
  exit 1
fi
if [[ ! -x ${repo_dir}/bin/hostsentry-agent ]]; then
  echo "${repo_dir}/bin/hostsentry-agent is missing. Run make build-agent first." >&2
  exit 1
fi
if ! getent group hostsentry >/dev/null; then
  echo "The hostsentry service group is missing. Run install-agent.sh first." >&2
  exit 1
fi
if ! openssl verify -CAfile "${repo_dir}/pki/ca.crt" "${repo_dir}/pki/agents/${agent_id}/agent.crt" >/dev/null; then
  echo "The agent certificate is not signed by this HostSentry CA." >&2
  exit 1
fi
if ! openssl x509 -in "${repo_dir}/pki/agents/${agent_id}/agent.crt" -noout -checkhost "${agent_id}" >/dev/null 2>&1; then
  echo "The agent certificate identity does not match ${agent_id}." >&2
  exit 1
fi
config=/etc/hostsentry/hostsentry.yaml
if [[ -e ${config} ]] && grep -Eq '^[[:space:]]*central:' "${config}"; then
  echo "${config} already has a central section; leaving it unchanged." >&2
  exit 1
fi

install -d -o root -g hostsentry -m 0750 /etc/hostsentry/pki
install -o root -g hostsentry -m 0640 "${repo_dir}/pki/ca.crt" /etc/hostsentry/pki/ca.crt
install -o root -g hostsentry -m 0640 "${repo_dir}/pki/agents/${agent_id}/agent.crt" /etc/hostsentry/pki/agent.crt
install -o root -g hostsentry -m 0640 "${repo_dir}/pki/agents/${agent_id}/agent.key" /etc/hostsentry/pki/agent.key
install -o root -g root -m 0755 "${repo_dir}/bin/hostsentry-agent" /usr/local/bin/hostsentry-agent

if [[ ! -e ${config} ]]; then
  install -o root -g hostsentry -m 0640 "${repo_dir}/examples/hostsentry.yaml" "${config}"
fi
cp -a "${config}" "${config}.bak.$(date +%Y%m%d%H%M%S)"
cat >> "${config}" <<EOF

central:
  url: ${server_url}
  agent_id: ${agent_id}
  ca_certificate: /etc/hostsentry/pki/ca.crt
  client_certificate: /etc/hostsentry/pki/agent.crt
  client_key: /etc/hostsentry/pki/agent.key
  queue_path: /var/lib/hostsentry/queue.jsonl
  queue_max_bytes: 10485760
  request_timeout: 10s
EOF
chown root:hostsentry "${config}"
chmod 0640 "${config}"
systemctl restart hostsentry-agent.service
systemctl --no-pager --full status hostsentry-agent.service
