#!/usr/bin/env bash
set -euo pipefail

if [[ ${EUID} -ne 0 ]]; then
  echo "Run this disposable systemd recovery test as root (for example: sudo $0)." >&2
  exit 1
fi

repo_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
binary=${repo_dir}/bin/hostsentry-agent
service=hostsentry-recovery-fixture.service
unit_file=/run/systemd/system/${service}
run_dir=/run/hostsentry-recovery-fixture-$$
data_dir=/var/lib/hostsentry/recovery-fixture-$$
config=${run_dir}/agent.yaml
report=${data_dir}/report.json
agent_stderr=${run_dir}/agent.stderr
fixture_binary=${run_dir}/hostsentry-agent
audit_log=${data_dir}/recovery.jsonl
rule=/etc/polkit-1/rules.d/50-hostsentry-recovery-fixture-$$.rules

if [[ ! -x ${binary} ]]; then
  echo "${binary} is missing. Build the current agent first with: make build-agent" >&2
  exit 1
fi
if ! id hostsentry >/dev/null 2>&1; then
  echo "The hostsentry service account is missing. Install the agent first." >&2
  exit 1
fi
for unit_dir in /etc/systemd/system /run/systemd/system /usr/lib/systemd/system /usr/local/lib/systemd/system; do
  if [[ -e ${unit_dir}/${service} ]]; then
    echo "${service} already exists under ${unit_dir}; refusing to replace it." >&2
    exit 1
  fi
done
if [[ -e ${rule} || -e ${run_dir} || -e ${data_dir} ]]; then
  echo "A recovery fixture path already exists; refusing to replace it." >&2
  exit 1
fi

cleanup() {
  set +e
  systemctl stop "${service}" >/dev/null 2>&1
  if [[ -e ${rule} ]]; then
    HOSTSENTRY_POLKIT_RULE=${rule} "${repo_dir}/scripts/configure-recovery-polkit.sh" --remove >/dev/null 2>&1
  fi
  rm -f -- "${unit_file}"
  systemctl daemon-reload >/dev/null 2>&1
  systemctl reset-failed "${service}" >/dev/null 2>&1
  rm -rf -- "${run_dir}" "${data_dir}"
}
trap cleanup EXIT INT TERM

install -d -o root -g hostsentry -m 0750 "${run_dir}"
install -d -o hostsentry -g hostsentry -m 0700 "${data_dir}"
install -o root -g hostsentry -m 0750 "${binary}" "${fixture_binary}"
cat >"${run_dir}/fixture.sh" <<EOF
#!/usr/bin/bash
if [[ ! -e '${data_dir}/service-started' ]]; then
  /usr/bin/touch '${data_dir}/service-started'
  exit 1
fi
exec /usr/bin/sleep infinity
EOF
chmod 0755 "${run_dir}/fixture.sh"

cat >"${unit_file}" <<EOF
[Unit]
Description=Temporary HostSentry recovery test fixture
StartLimitIntervalSec=0

[Service]
Type=simple
User=hostsentry
Group=hostsentry
ExecStart=${run_dir}/fixture.sh
Restart=no
EOF
chmod 0644 "${unit_file}"
systemctl daemon-reload

cat >"${config}" <<EOF
interval: 1s
process_limit: 5
sustain_for: 0s
thresholds:
  cpu_percent: 0
  memory_percent: 0
  disk_percent: 0
services:
  - ${service}
recovery:
  enabled: true
  dry_run: false
  audit_log: ${data_dir}/recovery.jsonl
  policies:
    - name: disposable-systemd-fixture
      enabled: true
      service: ${service}
      failure_for: 0s
      max_attempts: 1
      cooldown: 1m
      verification_timeout: 10s
EOF
chown root:hostsentry "${config}"
chmod 0640 "${config}"

HOSTSENTRY_AGENT_CONFIG=${config} HOSTSENTRY_POLKIT_RULE=${rule} \
  "${repo_dir}/scripts/configure-recovery-polkit.sh" "${service}"

systemctl start "${service}" >/dev/null 2>&1 || true
for _ in {1..10}; do
  if [[ $(systemctl show --property=ActiveState --value "${service}") == failed ]]; then
    break
  fi
  sleep 1
done
if [[ $(systemctl show --property=ActiveState --value "${service}") != failed ]]; then
  echo "Fixture did not enter systemd's failed state; refusing to test recovery." >&2
  exit 1
fi

echo "Fixture is failed. Running the agent as the unprivileged hostsentry account."
if ! runuser -u hostsentry -- "${fixture_binary}" -config "${config}" -once -output "${report}" 2>"${agent_stderr}"; then
  echo "Agent command failed; stderr follows:" >&2
  cat -- "${agent_stderr}" >&2
  exit 1
fi
if [[ $(systemctl show --property=ActiveState --value "${service}") != active ]]; then
  echo "The fixture did not recover. Check Polkit rule reload and systemd journal." >&2
  echo "Agent stderr:" >&2
  cat -- "${agent_stderr}" >&2
  echo "Recovery audit records:" >&2
  if [[ -r ${audit_log} ]]; then
    cat -- "${audit_log}" >&2
  else
    echo "No recovery audit file was written." >&2
  fi
  echo "Temporary unit journal:" >&2
  journalctl --no-pager -u "${service}" -n 30 >&2 || true
  echo "Recent Polkit journal:" >&2
  journalctl --no-pager --since '-5 minutes' -u polkit.service -n 50 >&2 || true
  exit 1
fi
if ! grep -q '"outcome": "succeeded"' "${report}" || ! grep -q '"verified": true' "${report}"; then
  echo "The service is active, but the agent did not report verified recovery." >&2
  exit 1
fi

echo "PASS: the unprivileged agent restarted and verified ${service}."
