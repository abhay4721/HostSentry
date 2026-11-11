#!/usr/bin/env bash
set -euo pipefail

repo_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
server_name=${1:-localhost}
if [[ ! ${server_name} =~ ^[A-Za-z0-9.-]+$ ]]; then
  echo "Provide a DNS name or IPv4 address for the server certificate." >&2
  exit 1
fi
command -v openssl >/dev/null || { echo "openssl is required." >&2; exit 1; }
cd -- "${repo_dir}"
umask 077
mkdir -p pki/agents
chmod 0700 pki pki/agents

if [[ ! -e .env ]]; then
  cat > .env <<EOF
POSTGRES_PASSWORD=$(openssl rand -hex 32)
HOSTSENTRY_BOOTSTRAP_ADMIN_EMAIL=admin@localhost
HOSTSENTRY_BOOTSTRAP_ADMIN_PASSWORD=$(openssl rand -hex 32)
HOSTSENTRY_METRICS_TOKEN=$(openssl rand -hex 32)
HOSTSENTRY_HEALTH_WEIGHTS={"cpu":20,"memory":20,"disk":20,"services":25,"network":10,"agent":5}
HOSTSENTRY_RECOVERY_ENABLED=false
HOSTSENTRY_RECOVERY_DRY_RUN=true
HOSTSENTRY_ANOMALY_ENABLED=true
HOSTSENTRY_ANOMALY_MIN_SAMPLES=20
HOSTSENTRY_ANOMALY_SIGMA=3
GRAFANA_ADMIN_USER=admin
GRAFANA_ADMIN_PASSWORD=$(openssl rand -hex 32)
HOSTSENTRY_API_BIND=127.0.0.1
HOSTSENTRY_UI_BIND=127.0.0.1
HOSTSENTRY_CONTAINER_UID=$(id -u)
HOSTSENTRY_CONTAINER_GID=$(id -g)
EOF
  chmod 0600 .env
  echo "Created .env with random credentials; API/UI bindings default to localhost."
else
  echo "Keeping existing .env."
fi
chmod 0600 .env
sed -i '/^HOSTSENTRY_ADMIN_TOKEN=/d' .env

metrics_token=$(awk -F= '$1 == "HOSTSENTRY_METRICS_TOKEN" { print $2; exit }' .env)
if [[ -z ${metrics_token} ]]; then
  metrics_token=$(openssl rand -hex 32)
  printf '\nHOSTSENTRY_METRICS_TOKEN=%s\n' "${metrics_token}" >> .env
fi
bootstrap_email=$(awk -F= '$1 == "HOSTSENTRY_BOOTSTRAP_ADMIN_EMAIL" { print $2; exit }' .env)
if [[ -z ${bootstrap_email} ]]; then printf '\nHOSTSENTRY_BOOTSTRAP_ADMIN_EMAIL=admin@localhost\n' >> .env; fi
bootstrap_password=$(awk -F= '$1 == "HOSTSENTRY_BOOTSTRAP_ADMIN_PASSWORD" { print $2; exit }' .env)
if [[ -z ${bootstrap_password} ]]; then printf 'HOSTSENTRY_BOOTSTRAP_ADMIN_PASSWORD=%s\n' "$(openssl rand -hex 32)" >> .env; fi
printf '%s' "${metrics_token}" > pki/prometheus.token
chmod 0644 pki/prometheus.token

if [[ ! -e pki/ca.crt || ! -e pki/ca.key ]]; then
  openssl genrsa -out pki/ca.key 3072
  openssl req -x509 -new -key pki/ca.key -sha256 -days 3650 \
    -subj "/CN=HostSentry Local CA" -out pki/ca.crt
  chmod 0600 pki/ca.key
  chmod 0644 pki/ca.crt
fi

if [[ ! -e pki/server.crt || ! -e pki/server.key ]]; then
  openssl genrsa -out pki/server.key 3072
  openssl req -new -key pki/server.key -subj "/CN=backend" -out pki/server.csr
  if [[ ${server_name} =~ ^[0-9]+(\.[0-9]+){3}$ ]]; then
    extra_san="IP.3 = ${server_name}"
  else
    extra_san="DNS.3 = ${server_name}"
  fi
  cat > pki/server.ext <<EOF
basicConstraints = CA:FALSE
keyUsage = digitalSignature, keyEncipherment
extendedKeyUsage = serverAuth
subjectAltName = @alt_names
[alt_names]
DNS.1 = backend
DNS.2 = localhost
IP.1 = 127.0.0.1
${extra_san}
EOF
  openssl x509 -req -in pki/server.csr -CA pki/ca.crt -CAkey pki/ca.key \
    -CAcreateserial -out pki/server.crt -days 825 -sha256 -extfile pki/server.ext
  rm -f pki/server.csr pki/server.ext
  chmod 0600 pki/server.key
  chmod 0644 pki/server.crt
fi

echo "Central certificates are ready. The first-run dashboard login is HOSTSENTRY_BOOTSTRAP_ADMIN_EMAIL/PASSWORD in .env."
echo "Issue each agent a unique client certificate with scripts/issue-agent-cert.sh <agent-id>."
