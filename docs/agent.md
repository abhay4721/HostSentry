# Standalone agent

## Operation

`hostsentry-agent` collects a snapshot at startup. With `-once`, it exits after writing the report. Otherwise, it samples at the configured interval until it receives SIGINT or SIGTERM. A failed collector does not discard valid sections; its error is recorded in the report's `warnings` array.

The output file path is replaced using a temporary file in the same directory followed by rename. The file is mode `0640`; directories created by the agent are mode `0750`. Standard output remains available for shell pipelines and scheduled jobs. Avoid directing a long-running agent to stdout under a service manager unless its log handling is configured for repeated JSON reports.

## Schema

The report has a top-level `schema_version`, UTC `collected_at`, system information, CPU, memory, disks, disk I/O, processes, interfaces, network counters, alerts, and warnings. `schema_version` changes when the report contract needs an incompatible update.

CPU utilization is a snapshot; disk and network I/O values are cumulative counters from the kernel. Rates can be calculated by comparing counter values across reports. Process entries are limited by `process_limit`, sorted by CPU and then resident memory.

## Threshold behavior

CPU and memory each have one threshold. Disk thresholds are tracked per mount point. A value must stay strictly above its threshold for `sustain_for`; returning to or below the threshold resets its timer. Timers are held in memory and reset when the agent restarts. Alerts are included in the report; the agent does not persist incidents or perform recovery.
