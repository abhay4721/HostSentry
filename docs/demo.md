# Local demo

This demo uses the current machine as a monitored host and a local central stack. It does not deliberately stop or damage a real service.

1. Prepare a central server using [the deployment guide](central-server.md), then start Compose.
2. Issue a unique agent certificate and copy the client cert, client key, and CA certificate to a test Linux machine.
3. Configure the agent's `central` section and a small set of explicitly monitored systemd services.
4. Install and start the agent, then confirm the host appears in the dashboard and `/api/v1/hosts`.
5. Review CPU, memory, disk, process, service and collection warning data. The dashboard displays the latest real agent snapshot; historical resource charts are in Grafana.
6. Create a disabled recovery policy for a disposable test service. Keep local and central dry-run enabled while reviewing the audit and incident flows.
7. Export the host inventory CSV from Reports and inspect the incident notification list.

To exercise an actual restart, use only a disposable VM and a test systemd unit, explicitly configure the agent's narrowly scoped systemd authorization, and disable dry-run after reviewing the policy. Do not experiment on a production service.
