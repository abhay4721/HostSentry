# Security

The agent does not accept remote commands, execute shell commands, kill processes, or delete files. It does not require root. Run it with the least-privileged account that can read the statistics you need.

Systemd monitoring is limited to configured unit names and uses the system bus. Recovery is disabled by default. If enabled, the only action is `RestartUnit` for a configured local service allowlist. Centrally assigned policies cannot name a service outside that allowlist, and local recovery opt-in and dry-run settings remain authoritative. The deployment installer grants no systemd management permission. Administrators must provide an appropriately narrow local authorization policy before restarts can succeed. Recovery attempts are time-limited, capped, cooldown-protected, and written to a mode-0600 JSONL audit file.

Reports may include hostnames, process names and IDs, mount points, and resource usage. Store reports with restrictive file permissions and treat them as operational data.

Process visibility varies with `/proc` mount settings, namespaces, and kernel hardening. Missing process information is not a reason to grant broad privileges.

Central dashboard accounts use bcrypt password hashes and 12-hour opaque sessions whose SHA-256 hashes are stored in PostgreSQL. Roles are enforced by the API: viewers are read-only, operators can update incident status, and admins manage users and operational controls. Session tokens are held in browser session storage and revoked on sign-out, password reset, or account disable. Use HTTPS end-to-end and protect the bootstrap credentials in `.env`; remove `HOSTSENTRY_BOOTSTRAP_ADMIN_PASSWORD` from `.env` after the first admin account is established.

Optional SMTP delivery requires STARTTLS or implicit TLS and validates the server certificate. Telegram and GitHub use HTTPS. Notifications are best-effort and are not durably retried if an external provider is unavailable. Store provider tokens and SMTP credentials in `.env` with mode `0600` and grant only issue-write access to the GitHub token.
