# Architecture

HostSentry currently consists of a local Linux process. The agent reads system information and kernel counters, then writes a versioned JSON report. It needs no backend, database, or network connection.

## Packages

- `cmd/hostsentry-agent` handles command-line flags, signals, logging, and report output.
- `internal/agent` defines the report schema, validates configuration, tracks threshold duration, and collects Linux metrics.

## Collection

Collectors run independently. If one section cannot be read, the report includes a warning and retains the data from other sections. A process may exit during collection, so entries that cannot be read are skipped. The process list is capped by configuration.

Disk and network I/O are reported as cumulative counters. A consumer can calculate rates by comparing successive reports and their timestamps. The agent does not store metric history.

## Boundaries

The agent does not receive remote commands, connect to a central service, or change host state. It does not manage systemd services or run recovery actions.
