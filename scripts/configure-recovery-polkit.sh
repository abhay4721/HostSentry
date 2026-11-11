#!/usr/bin/env bash
set -euo pipefail

rule=${HOSTSENTRY_POLKIT_RULE:-/etc/polkit-1/rules.d/50-hostsentry-recovery.rules}
config=${HOSTSENTRY_AGENT_CONFIG:-/etc/hostsentry/hostsentry.yaml}

if [[ ${EUID} -ne 0 ]]; then
  echo "Run this command as root (for example: sudo $0 <service.service> [...])." >&2
  exit 1
fi
if [[ ! ${rule} =~ ^/etc/polkit-1/rules\.d/[A-Za-z0-9_.-]+\.rules$ ]]; then
  echo "Polkit rule path must be a .rules file inside /etc/polkit-1/rules.d." >&2
  exit 2
fi

if [[ ${1:-} == "--remove" ]]; then
  if (($# != 1)); then
    echo "Usage: sudo $0 --remove" >&2
    exit 2
  fi
  if [[ -e ${rule} ]]; then
    if ! grep -Fq 'HostSentry managed service restart authorization' "${rule}"; then
      echo "Refusing to remove ${rule}: it does not contain the HostSentry marker." >&2
      exit 1
    fi
    rm -- "${rule}"
    echo "Removed ${rule}. Restart polkit if your distribution does not reload rules automatically."
  else
    echo "No HostSentry recovery rule is installed."
  fi
  exit 0
fi

if [[ ! -r ${config} ]]; then
  echo "Agent config not found: ${config}. Install the agent and list approved units under services first." >&2
  exit 1
fi
if (($# == 0)); then
  echo "Usage: sudo $0 <service.service> [service.service ...] | --remove" >&2
  exit 2
fi
if ! command -v install >/dev/null 2>&1; then
  echo "The install command is required." >&2
  exit 1
fi
if [[ -e ${rule} ]] && ! grep -Fq 'HostSentry managed service restart authorization' "${rule}"; then
  echo "Refusing to replace ${rule}: it does not contain the HostSentry marker." >&2
  exit 1
fi

declare -A seen=()
services=()
for service in "$@"; do
  if [[ ! ${service} =~ ^[A-Za-z0-9_.:@-]+\.service$ ]]; then
    echo "Invalid systemd service name: ${service}" >&2
    exit 2
  fi
  if [[ -n ${seen[${service}]:-} ]]; then
    echo "Duplicate service: ${service}" >&2
    exit 2
  fi
  seen["${service}"]=1
  if ! awk -v target="${service}" '
    /^services:[[:space:]]*($|#)/ { in_services=1; next }
    /^[^[:space:]#]/ { in_services=0 }
    in_services && $1 == "-" && $2 == target { found=1 }
    END { exit !found }
  ' "${config}"; then
    echo "${service} is not listed under services in ${config}." >&2
    exit 1
  fi
  services+=("${service}")
done

temporary=$(mktemp)
trap 'rm -f -- "${temporary}"' EXIT
{
  echo '// HostSentry managed service restart authorization.'
  echo 'polkit.addRule(function(action, subject) {'
  echo '  if (action.id !== "org.freedesktop.systemd1.manage-units" || subject.user !== "hostsentry") {'
  echo '    return polkit.Result.NOT_HANDLED;'
  echo '  }'
  printf '  var allowedUnits = [ '
  for service in "${services[@]}"; do
    printf '"%s", ' "${service}"
  done
  echo '];'
  echo '  if (action.lookup("verb") === "restart" && allowedUnits.indexOf(action.lookup("unit")) !== -1) {'
  echo '    return polkit.Result.YES;'
  echo '  }'
  echo '  return polkit.Result.NOT_HANDLED;'
  echo '});'
} >"${temporary}"

install -D -o root -g root -m 0644 "${temporary}" "${rule}"
echo "Installed ${rule}; hostsentry may request only restart for: ${services[*]}"
echo "Recovery remains controlled by the agent config and policy settings. Remove with: sudo $0 --remove"
