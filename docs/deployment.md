# Standalone deployment

The standalone agent runs directly on a systemd-based Linux host and does not need a server or network access. On Arch Linux, install Go (`sudo pacman -S go`), then from the repository root run:

```sh
make test
make build
./bin/hostsentry-agent -once
```

The one-shot command prints a real report as JSON. Review it before enabling the background service. Install the service with:

```sh
sudo ./scripts/install-agent.sh
```

The installer installs the binary at `/usr/local/bin/hostsentry-agent`, creates a non-login `hostsentry` account, installs the default config only if one is not already present, and enables the service at boot. The service runs without elevated privileges and writes the latest report to `/var/lib/hostsentry/report.json`.

Inspect operation with:

```sh
systemctl status hostsentry-agent
journalctl -u hostsentry-agent -f
cat /var/lib/hostsentry/report.json
```

Change settings in `/etc/hostsentry/hostsentry.yaml`, then restart the service:

```sh
sudo systemctl restart hostsentry-agent
```

Remove the service and installed binary while retaining configuration and reports with:

```sh
sudo ./scripts/uninstall-agent.sh
```

The unit applies systemd filesystem and privilege restrictions. As an unprivileged process, the agent may not see process or mount details hidden by kernel permissions or container boundaries; collection warnings are included in the JSON report. Systemd monitoring is limited to units listed under `services` in the config. Recovery stays disabled until an operator enables it and defines an explicit service allowlist and policy.

## Connect this agent to the central server

On the central server, create one client certificate for this host:

```sh
./scripts/issue-agent-cert.sh arch-linux
```

On the agent host, make the CA certificate, client certificate, and key available in the repository checkout, then run:

```sh
sudo ./scripts/connect-agent.sh arch-linux
```

The script installs the latest built agent and client identity with restricted ownership, adds the central endpoint to the existing agent config, backs up that config, and restarts the service. Pass a different HTTPS origin as the second argument when the central server is remote, for example `https://hostsentry.example.com:8444`. The agent will report every 30 seconds and queue reports while the server is unreachable.
