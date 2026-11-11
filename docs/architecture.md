# Architecture

HostSentry is split into a local Linux agent and an optional central stack. The agent remains useful when no central server is configured and continues monitoring while the network is unavailable.

## Agent

- `cmd/hostsentry-agent` loads strict YAML configuration, handles signals, writes atomic JSON reports, and optionally sends reports to the server.
- `internal/agent` collects procfs/gopsutil metrics, reads configured systemd units over D-Bus, evaluates local thresholds and recovery policy, keeps a bounded durable report queue, and uses mTLS for outbound report delivery.
- Recovery supports only a constrained systemd restart operation for locally allowlisted services. It records verification outcomes and audit history. No shell command or remote arbitrary action is accepted.

## Central stack

- `cmd/hostsentry-server` serves a TLS REST API and Prometheus endpoint.
- `internal/server` authenticates agents by client certificate identity, stores the latest report per host, maintains normalized monitored-service and heartbeat state, tracks per-host policy versions and dashboard notifications, derives deduplicated incidents, and stores recovery history in PostgreSQL.
- Centrally assigned policies use a closed action schema, are versioned, and are checked against each agent's local allowlist before they can run.
- `frontend` is a React/TypeScript/Vite dashboard. Caddy serves it over TLS; users sign in to the API and receive a short-lived opaque session token.
- Prometheus retains time-series data; PostgreSQL keeps host inventory, the latest snapshot, operational state, notifications, audit events, incidents, and recovery execution history.
- An optional central statistical detector builds per-host CPU, memory, and mount utilization baselines with Welford's online mean/variance, then creates incidents for high outliers after a configurable minimum sample count.
- Grafana and Alertmanager run as optional local Compose services.
- The API stores bcrypt password hashes and role-scoped sessions. Admins manage users and recovery policies, operators may update incident status, and viewers have read-only access.

Agents initiate outbound HTTPS connections. The central server never opens a shell, connects back to an agent, or sends an unbounded action. PostgreSQL and monitoring interfaces are not exposed publicly by Compose defaults.

## Report processing

Each report has a schema version and UTC timestamp. Collectors return partial data with warnings when a kernel interface is unavailable or permission is denied. The central API updates the host's latest report transactionally, creates or updates incidents by a stable condition fingerprint, resolves conditions that disappear, and inserts new recovery records idempotently.

CPU utilization is a snapshot; disk and network I/O values are cumulative counters. Prometheus scrapes latest values from the API to build history. Authenticated host-detail endpoints query only fixed, bounded Prometheus expressions for CPU, memory, disk, and network charts. Offline delivery is stored as bounded JSONL on the agent and retried with exponential backoff.

## Boundaries

The dashboard provides current host state and recent API-backed incident notifications. Optional SMTP, Telegram, and GitHub issue transports send only newly created incidents and can filter by severity and incident type. Delivery is best-effort; Alertmanager remains available for independently managed external notifications. Long-term metric charts come from Prometheus. Health scoring uses configurable weights and reports a score from 0 to 100; it is not a reliability guarantee. Systemd restart permission is a local administrator decision; installation does not grant it.
