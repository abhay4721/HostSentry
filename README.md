# HostSentry

HostSentry is an open-source Linux fleet health agent and optional central dashboard. The agent can run by itself, collect real system metrics, and write JSON reports. The central deployment adds PostgreSQL-backed host and incident views, Prometheus, Grafana, and Alertmanager.

## Current capabilities

- CPU, memory, swap, disk, inode, disk I/O, network, process, OS, kernel, and uptime collection.
- Configurable thresholds with sustained-duration evaluation.
- Optional systemd service state over D-Bus.
- Recovery disabled by default; when explicitly enabled, the only available action requests a restart of an allowlisted service, verifies the result, and records an audit entry.
- Optional outbound mutual-TLS report delivery with an on-disk bounded queue and retry backoff.
- PostgreSQL-backed central fleet, incident, recovery, host grouping, user, and audit APIs.
- Responsive dashboard with role-based sign-in, host and group views, incidents, recovery policies, reports, and settings.
- Optional SMTP, Telegram, and GitHub issue incident delivery, plus Prometheus, Grafana, and Alertmanager deployment.
- Arch-compatible systemd installation that runs the agent as a non-root service account.

## Standalone Arch Linux agent

Requires Go 1.25 or newer. Install Go with `sudo pacman -S go`, then run:

```sh
make fmt vet test build
./bin/hostsentry-agent -once
sudo ./scripts/install-agent.sh
```

See [agent operations](docs/agent.md) and [standalone deployment](docs/deployment.md).

## Linux compatibility

The agent targets systemd-based Ubuntu, Debian, Fedora, Arch Linux, and Amazon Linux 2023 hosts. It reads Linux procfs and systemd over the system D-Bus; collection permissions and service-manager policy vary by distribution. This workspace has been runtime-checked on Arch Linux, and CI builds/tests on Ubuntu. Fedora, Debian, and Amazon Linux runtime validation remains outstanding. The installer uses standard `systemd`, `getent`, `groupadd`, and `useradd` tools and does not install distribution packages.

## Central deployment

Requires Docker Engine with Compose and OpenSSL. Generate local certificates and secrets, then start the stack:

```sh
./scripts/setup-central.sh 192.168.1.20
docker compose up --build -d
```

The script defaults API and dashboard ports to localhost. Configure `HOSTSENTRY_API_BIND` in `.env` for monitored machines on the LAN, and open only the required port in the host firewall. Issue one client certificate per agent with `scripts/issue-agent-cert.sh <agent-id>`.

See [central deployment](docs/central-server.md) and the [API reference](docs/api.md).

## Development

```sh
make fmt vet test build
```

Go modules are pinned by `go.mod` and `go.sum`. The React application is under `frontend/`; its production bundle is built into the frontend image. See [architecture](docs/architecture.md) and [security](docs/security.md).

## Project status

HostSentry is under active development. SMTP and Telegram notification delivery is best-effort and is attempted once when an incident is first created. Review the [recovery guide](docs/recovery.md) and configure narrowly scoped systemd authorization before enabling live automatic recovery.

## License

Apache-2.0. See [LICENSE](LICENSE).
