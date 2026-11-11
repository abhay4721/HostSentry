#!/usr/bin/env bash
set -euo pipefail

repo_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
agent_id=${1:-}
if [[ ! ${agent_id} =~ ^[A-Za-z0-9_-]{1,128}$ ]]; then
  echo "Usage: $0 <agent-id> (letters, digits, hyphen, underscore; max 128 characters)" >&2
  exit 2
fi
if [[ ! -r ${repo_dir}/pki/ca.key || ! -r ${repo_dir}/pki/ca.crt ]]; then
  echo "Central CA is missing. Run scripts/setup-central.sh first." >&2
  exit 1
fi

umask 077
agent_dir=${repo_dir}/pki/agents/${agent_id}
mkdir -p "${agent_dir}"
if [[ -e ${agent_dir}/agent.key || -e ${agent_dir}/agent.crt ]]; then
  echo "Agent certificate already exists for ${agent_id}; refusing to overwrite it." >&2
  exit 1
fi
openssl genrsa -out "${agent_dir}/agent.key" 3072
openssl req -new -key "${agent_dir}/agent.key" -subj "/CN=${agent_id}" -out "${agent_dir}/agent.csr"
cat > "${agent_dir}/agent.ext" <<EOF
basicConstraints = CA:FALSE
keyUsage = digitalSignature, keyEncipherment
extendedKeyUsage = clientAuth
subjectAltName = DNS:${agent_id}
EOF
openssl x509 -req -in "${agent_dir}/agent.csr" -CA "${repo_dir}/pki/ca.crt" \
  -CAkey "${repo_dir}/pki/ca.key" -CAcreateserial -out "${agent_dir}/agent.crt" \
  -days 825 -sha256 -extfile "${agent_dir}/agent.ext"
rm -f "${agent_dir}/agent.csr" "${agent_dir}/agent.ext"
chmod 0600 "${agent_dir}/agent.key"
chmod 0644 "${agent_dir}/agent.crt"
echo "Created client certificate for ${agent_id} in ${agent_dir}; copy agent.crt and agent.key securely to that host."
openssl x509 -in "${agent_dir}/agent.crt" -noout -fingerprint -sha256
