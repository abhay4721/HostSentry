# HostSentry

HostSentry is a Linux host monitoring agent written in Go. It collects system and process statistics and writes them as JSON. It runs locally without a server or network connection.

## Features

- CPU utilization by core, CPU time counters, and load averages.
- RAM, swap, and memory pressure when the kernel exposes it.
- Filesystem capacity, inode use, read-only mounts, and disk I/O counters.
- Network interface state and per-interface traffic counters.
- A bounded process list with CPU, resident memory, thread count, status, and start time.
- Configurable CPU, memory, and disk thresholds with sustained-duration checks.
- JSON output to stdout or an atomically replaced report file.

The agent is read-only. It does not monitor systemd services, perform recovery, or send data to a central server.

## Build

Requires Go 1.23 or newer.

```sh
go mod tidy
go test ./...
go build -o hostsentry-agent ./cmd/hostsentry-agent
```

Run once and print a report:

```sh
./hostsentry-agent -once
```

Write periodic reports to a file:

```sh
./hostsentry-agent -config examples/hostsentry.yaml -output /var/lib/hostsentry/report.json
```

Logs are written to stderr. The output file is replaced atomically and uses mode `0640`; created directories use mode `0750`. Use `-version` to print the build version.

## Configuration

See [examples/hostsentry.yaml](examples/hostsentry.yaml). Durations use Go syntax such as `30s` and `2m`. Threshold values are percentages from 0 through 100. Set a threshold to `0` to disable it. An alert is included in the report after a value stays above its threshold for `sustain_for`. Disk thresholds are tracked separately for each mount point.

## Report behavior

Each report includes a `schema_version` and UTC collection timestamp. Collection errors are listed in `warnings`; other sections are still returned when possible. Network and disk I/O values are cumulative kernel counters, not rates. The process list is sorted by CPU use, then resident memory, and limited by `process_limit`.

Process CPU values can be zero when a process has not accumulated measurable CPU time. Process and mount visibility depends on the account's permissions, kernel settings, and container boundaries. Run the agent as an ordinary user; do not grant broad privileges to remove individual warnings.

## Linux support

The collector uses Linux procfs and gopsutil's Linux interfaces. It is intended for systemd-based Ubuntu, Debian, Fedora, Arch Linux, and Amazon Linux 2023. The current agent does not interact with systemd. In containers, memory and mount readings may describe the container rather than the full machine. Memory pressure is optional and requires kernel support for Pressure Stall Information at `/proc/pressure/memory`.

## Development

Run the test suite with `go test ./...`. The [Linux agent workflow](.github/workflows/agent.yml) runs tests and `go vet` on Ubuntu and builds Linux amd64 and arm64 binaries on pushes to `main` or `master`, pull requests, and manual dispatch.

See [agent operation](docs/agent.md), [architecture](docs/architecture.md), and [security](docs/security.md).

## License

Apache-2.0. See [LICENSE](LICENSE).
