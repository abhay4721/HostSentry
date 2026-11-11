# Troubleshooting

## Agent service does not start

```sh
sudo systemctl status hostsentry-agent
sudo journalctl -u hostsentry-agent -b --no-pager
```

Check that `/etc/hostsentry/hostsentry.yaml` exists and is readable by the service account, paths in the config are writable where required, and YAML values use valid durations. Run one foreground collection with `sudo -u hostsentry /usr/local/bin/hostsentry-agent -config /etc/hostsentry/hostsentry.yaml -once` to see a report without waiting for the systemd interval.

## Collection warnings

Some kernel interfaces are restricted by container, namespace, or host policy. Collection remains partial and reports warnings instead of treating unavailable values as zero. Check the warning text and permissions for the relevant `/proc`, `/sys`, or systemd D-Bus interface. Only grant additional access when needed.

## Central API or dashboard is unreachable

```sh
docker compose ps
docker compose logs --tail=100 backend frontend postgres
curl --cacert pki/ca.crt https://127.0.0.1:8444/healthz
```

Confirm `.env` tokens are present, the API and UI bindings match the intended client network, the server certificate SAN contains the address used by agents, and the agent trusts the configured CA. For mTLS, the client certificate CN must exactly match `central.agent_id` and must not be revoked.

## Reports are queued but not delivered

Inspect agent logs and verify DNS/routing, TCP 8444 reachability, certificate paths and permissions, server certificate name, and client certificate identity. The local JSONL queue is bounded; the oldest snapshots may be discarded once its configured size limit is reached.

## Recovery did not restart a service

Recovery is disabled by default. Check `recovery.enabled`, `recovery.dry_run`, the local service allowlist, the server-wide switch and dry-run setting, policy assignment, cooldown, attempt limits, and audit logs. A service requiring approval will not restart in the current release. The systemd service installer does not grant privilege escalation.

## Compose reports permission errors

The setup script runs containers with the invoking user's numeric UID/GID so the backend can read the private server key. Check ownership and mode on `pki/server.key`, `.env`, and mounted files. Keep private keys inaccessible to other users.
