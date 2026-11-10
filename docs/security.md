# Security

The agent is read-only. It does not accept network commands, execute shell commands, manage services, kill processes, or delete files. It does not require root. Run it with the least-privileged account that can read the statistics you need.

Reports may include hostnames, process names and IDs, mount points, and resource usage. Store reports with restrictive file permissions and treat them as operational data.

Process visibility varies with `/proc` mount settings, namespaces, and kernel hardening. Missing process information is not a reason to grant broad privileges.
