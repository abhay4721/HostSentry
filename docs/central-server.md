# Central server deployment

The central stack uses Docker Compose, PostgreSQL, the Go API, Caddy, Prometheus, Grafana, and Alertmanager. PostgreSQL and monitoring interfaces bind to localhost only. The API and dashboard also default to localhost until their bind addresses are explicitly changed.

## Prepare certificates and secrets

From the repository root, pass the DNS name or IPv4 address agents will use:

```sh
./scripts/setup-central.sh 192.168.1.20
```

The script creates `.env`, a local certificate authority, and a server certificate with `backend`, `localhost`, and the supplied name or address in its SANs. `.env` contains the generated bootstrap admin email and password; use these for the first dashboard sign-in, then create another admin account. Keep `.env`, `pki/ca.key`, and all private keys out of source control and restrict access to them.

For agents on another machine, edit `.env` and set `HOSTSENTRY_API_BIND` to the central server's LAN address. Leave the UI binding on `127.0.0.1` unless LAN dashboard access is needed. Permit inbound TCP 8444 only from the agent network and TCP 8443 only from trusted dashboard clients. PostgreSQL, Prometheus, Grafana, and Alertmanager are not exposed beyond localhost.

The host health score uses weights from `HOSTSENTRY_HEALTH_WEIGHTS`, a JSON object whose nonnegative CPU, memory, disk, services, network, and agent weights must sum to 100. Defaults are 20/20/20/25/10/5. Component scores are shown by the API as well as the total; the score is a summary, not a reliability guarantee.

Optional incident notifications can be delivered by SMTP, Telegram, or a GitHub issue. Set the relevant `HOSTSENTRY_SMTP_*`, `HOSTSENTRY_TELEGRAM_*`, or `HOSTSENTRY_GITHUB_*` variables in `.env`, then restart the backend. GitHub requires a token with issue write access and `HOSTSENTRY_GITHUB_REPOSITORY=owner/repository`; labels are optional. `HOSTSENTRY_NOTIFY_SEVERITIES` defaults to `critical,warning`; `HOSTSENTRY_NOTIFY_TYPES` can further limit delivery to comma-separated incident types. SMTP requires STARTTLS or implicit TLS on port 465. Sends are best-effort and happen once when a new incident is created; existing incidents are not repeatedly notified.

## Start the stack

```sh
docker compose up --build -d
docker compose ps
docker compose logs -f backend
```

The dashboard is at `https://<server-name>:8443`, the agent API is at `https://<server-name>:8444`, and local-only Grafana is at `http://127.0.0.1:3000`. The browser will need to trust `pki/ca.crt` to avoid a certificate warning. Grafana credentials are in the local `.env` file.

## Register an agent

Issue a unique client certificate using the exact agent ID that will be configured on the host:

```sh
./scripts/issue-agent-cert.sh arch-web-01
```

Copy that agent's `agent.crt` and `agent.key` plus `pki/ca.crt` to the monitored host over a secure channel. Keep the private key readable only by the agent account. The certificate's Common Name is the agent ID; the central API checks it against the request identity. Registration occurs on the first authenticated report.

Add the following to `/etc/hostsentry/hostsentry.yaml` on the agent, using paths readable by its service account:

```yaml
central:
  url: https://192.168.1.20:8444
  agent_id: arch-web-01
  ca_certificate: /etc/hostsentry/pki/ca.crt
  client_certificate: /etc/hostsentry/pki/agent.crt
  client_key: /etc/hostsentry/pki/agent.key
  queue_path: /var/lib/hostsentry/queue.jsonl
  queue_max_bytes: 10485760
  request_timeout: 10s
```

Restart the local agent with `sudo systemctl restart hostsentry-agent`. The agent initiates HTTPS connections, queues reports on disk when the API is unavailable, retries with exponential backoff, and removes queued reports only after a successful response. Queue size is bounded; when full, older snapshots may be coalesced or dropped while pending recovery records are carried forward.

## Data and limits

The API stores host state, normalized monitored services, latest heartbeats, per-host policy versions, dashboard notifications, incidents and their event timelines, recovery history, users, sessions, and audit events in PostgreSQL. Prometheus scrapes the API's `/metrics` endpoint for time series. Agent ingestion requires verified client certificates. Dashboard users sign in over HTTPS; the API enforces roles on each route and stores only a hash of each session token.

Recovery policies are administered through the authenticated `/api/v1/policies` API and assigned to registered host IDs. Only `restart_service` is accepted. Agents poll assigned policies using mTLS and validate each service against their local `services` allowlist. Agents also require local `recovery.enabled: true` and `recovery.allow_remote_policies: true`. Local dry-run always wins; the server-wide switch defaults disabled and server-wide dry-run defaults enabled.

The stack uses a local CA and admin-issued certificates. The API supports a database-backed denylist by certificate SHA-256 fingerprint; issue a replacement certificate after revocation. The CA signing key remains on the central host, so protect it and rotate the CA if that key is lost. Keep PostgreSQL and Prometheus data volumes in backups appropriate to your environment.
