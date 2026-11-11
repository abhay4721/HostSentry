# API reference

All endpoints use HTTPS in the Compose deployment and are versioned under `/api/v1`.

## Agent endpoint

`POST /api/v1/agent/reports` accepts the report envelope from the agent. It requires a verified client certificate whose Common Name matches the `X-HostSentry-Agent` header. The body is limited to 4 MiB and contains an idempotency ID and a versioned health report. Reports update the host's latest state, incident state, and recovery history transactionally.

## Dashboard endpoints

Dashboard routes require a session token in `Authorization: Bearer <token>`. Sign in with `POST /api/v1/auth/login`. Tokens expire after 12 hours and are stored as SHA-256 hashes in PostgreSQL. Roles are `admin`, `operator`, and `viewer`: viewers can read, operators can update incident status, and admins manage users, groups, policies, and certificate revocation.

| Method | Path | Behavior |
| --- | --- | --- |
| GET | `/healthz` | Database readiness |
| GET | `/metrics` | Prometheus exposition (separate bearer token) |
| POST | `/api/v1/auth/login` | Create a 12-hour user session |
| GET | `/api/v1/auth/me` | Current user and role |
| POST | `/api/v1/auth/logout` | Revoke current session |
| GET | `/api/v1/users` | List users (admin) |
| POST | `/api/v1/users` | Create user (admin) |
| PATCH | `/api/v1/users/{id}` | Change role, disable account, or reset password (admin) |
| GET | `/api/v1/hosts?limit=50&offset=0` | Paginated host summaries; add `include_report=true` for latest per-host snapshots |
| GET | `/api/v1/hosts/{id}` | Host and latest report |
| GET | `/api/v1/hosts/{id}/metrics?metric=cpu&range=6h` | Bounded historical CPU, memory, disk, or network series from Prometheus |
| GET | `/api/v1/incidents?status=active&host_id={id}` | Unresolved incidents; a specific lifecycle state such as `open` or `resolved` can also be requested |
| PATCH | `/api/v1/incidents/{id}` | Set acknowledged, investigating, suppressed, or resolved |
| GET | `/api/v1/incidents/{id}/events` | Incident detection, status, and resolution timeline |
| GET | `/api/v1/recoveries?limit=50&offset=0` | Recovery execution history |
| GET | `/api/v1/policies` | List policies (authenticated user) |
| POST | `/api/v1/policies` | Create a fixed-action policy for registered hosts |
| PUT | `/api/v1/policies/{id}` | Replace a policy and its host assignments |
| DELETE | `/api/v1/policies/{id}` | Disable a policy |
| POST | `/api/v1/agents/revoke-certificate` | Revoke a client certificate by SHA-256 fingerprint |
| GET | `/api/v1/groups` | List host groups (authenticated user) |
| POST/PUT/DELETE | `/api/v1/groups` | Manage host groups (admin) |
| GET | `/api/v1/notifications` | Incident notification feed |
| GET | `/api/v1/reports/hosts.csv` | Current fleet inventory CSV |
| GET | `/api/v1/settings` | Non-secret central runtime settings |

Agents use `GET /api/v1/agent/policies` with their mTLS identity to retrieve assigned policies. Policies accept only `restart_service`, and the agent independently checks its local service allowlist and recovery opt-in before acting.

Certificate revocation request bodies contain `host_id`, `fingerprint` (SHA-256 hex, with or without colons), and an optional `reason`. Revocation is enforced on every agent API request after TLS chain verification.

Errors use `{ "error": { "code": "...", "message": "..." } }`. Limits are capped at 200 and offsets at 100,000. No API endpoint accepts a shell command or a remote recovery action.
