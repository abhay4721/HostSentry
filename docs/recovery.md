# Recovery engine and policy configuration

HostSentry recovery is opt-in and supports one bounded operation: restarting an explicitly configured systemd service. The agent accepts no shell commands, process-kill requests, or filesystem deletion requests.

## Local policy

Set the services list to units the agent may inspect. Enable recovery only after reviewing the unit list and the systemd D-Bus permissions available to the agent. Dry-run is enabled by default.

```yaml
services:
  - nginx.service
recovery:
  enabled: false
  dry_run: true
  audit_log: /var/log/hostsentry/recovery.jsonl
  policies:
    - name: nginx-restart
      enabled: false
      service: nginx.service
      failure_for: 30s
      max_attempts: 3
      cooldown: 5m
      verification_timeout: 30s
      require_approval: true
```

The service must appear in the local `services` allowlist and be a valid `.service` unit. Automatic restart is triggered only when systemd reports the unit as `failed`; an intentionally stopped `inactive` unit is left alone. Attempts are capped, cooldown state is persisted across agent restarts, audit records use mode `0600`, and corrupted recovery state fails closed. Recovery does not run as root and the installer does not grant it permission automatically.

If you choose to enable live recovery, the optional setup script creates a Polkit rule for the exact units you name, and only for systemd's `restart` verb. Each unit must already be listed under `services` in `/etc/hostsentry/hostsentry.yaml`:

```sh
sudo ./scripts/configure-recovery-polkit.sh nginx.service
```

Pass every approved unit as an argument. Review the generated `/etc/polkit-1/rules.d/50-hostsentry-recovery.rules` before enabling recovery. Remove the rule with `sudo ./scripts/configure-recovery-polkit.sh --remove`. Polkit rule reload behavior depends on the distribution; restart `polkit.service` if the rule is not recognized. Keep `recovery.enabled: false` until the policy, dry-run output, and authorization rule have been reviewed.

To test a live restart without changing the installed agent config or touching an existing service, build the current agent and run the disposable fixture:

```sh
make build-agent
sudo ./scripts/test-recovery-fixture.sh
```

It creates a temporary service that fails on its first start, installs a temporary Polkit rule for that exact unit and the `restart` verb, then runs the agent as the unprivileged `hostsentry` account. The fixture stops, its unit and rule are removed, and its temporary reports are deleted on exit.

## Central policies

Central policy assignment is disabled unless local recovery and `allow_remote_policies` are both enabled. The server-wide recovery switch defaults off and server dry-run defaults on. An agent validates downloaded policy schema and service allowlists again. Local dry-run takes precedence. A policy requiring approval remains non-executing until an approval workflow is configured; the current dashboard does not provide an approval executor.

Create policies in the dashboard or through the authenticated API. Newly created policies start disabled. Assign them only to registered hosts and first validate behavior in dry-run. See [central deployment](central-server.md) and [API reference](api.md).

## Audit data

The agent writes local recovery attempts to its configured JSONL audit file and includes execution results in queued reports. The server keeps deduplicated recovery history. Protect both locations and include them in your retention and backup plan.
