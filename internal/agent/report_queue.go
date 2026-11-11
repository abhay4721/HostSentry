package agent

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

type queuedReport struct {
	ID     string `json:"id"`
	Report Report `json:"report"`
}

type ReportQueue struct {
	mu       sync.Mutex
	path     string
	maxBytes int64
}

func NewReportQueue(path string, maxBytes int64) *ReportQueue {
	return &ReportQueue{path: path, maxBytes: maxBytes}
}

func (q *ReportQueue) Push(item queuedReport) error {
	line, err := json.Marshal(item)
	if err != nil {
		return fmt.Errorf("encode queued report: %w", err)
	}
	if int64(len(line)+1) > q.maxBytes {
		return errors.New("report is larger than the configured central queue limit")
	}
	q.mu.Lock()
	defer q.mu.Unlock()
	lines, err := q.readLocked()
	if err != nil {
		return err
	}
	lines = append(lines, append(line, '\n'))
	total := int64(0)
	for _, entry := range lines {
		total += int64(len(entry))
	}
	// Drop oldest snapshots when the bounded queue is full; the newest health
	// state is more useful than an unbounded backlog of stale samples.
	for len(lines) > 1 && total > q.maxBytes {
		var dropped queuedReport
		if err := json.Unmarshal(bytes.TrimSpace(lines[0]), &dropped); err != nil {
			return fmt.Errorf("decode queued report while trimming: %w", err)
		}
		var next queuedReport
		if err := json.Unmarshal(bytes.TrimSpace(lines[1]), &next); err != nil {
			return fmt.Errorf("decode queued report while trimming: %w", err)
		}
		next.Report.Recoveries = mergeRecoveries(dropped.Report.Recoveries, next.Report.Recoveries)
		merged, err := json.Marshal(next)
		if err != nil {
			return fmt.Errorf("encode retained recovery history: %w", err)
		}
		total -= int64(len(lines[0])) + int64(len(lines[1]))
		lines = lines[1:]
		lines[0] = append(merged, '\n')
		total += int64(len(lines[0]))
	}
	if total > q.maxBytes {
		return errors.New("report queue limit cannot preserve pending recovery history")
	}
	return q.writeLocked(lines)
}

func mergeRecoveries(older, newer []RecoveryExecution) []RecoveryExecution {
	merged := make([]RecoveryExecution, 0, len(older)+len(newer))
	seen := make(map[string]struct{}, len(older)+len(newer))
	for _, execution := range append(append([]RecoveryExecution(nil), older...), newer...) {
		key := execution.Policy + "\x00" + execution.Service + "\x00" + execution.StartedAt.UTC().Format(time.RFC3339Nano)
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		merged = append(merged, execution)
	}
	return merged
}

func (q *ReportQueue) Peek() (queuedReport, bool, error) {
	q.mu.Lock()
	defer q.mu.Unlock()
	lines, err := q.readLocked()
	if err != nil || len(lines) == 0 {
		return queuedReport{}, false, err
	}
	var item queuedReport
	if err := json.Unmarshal(bytes.TrimSpace(lines[0]), &item); err != nil {
		return queuedReport{}, false, fmt.Errorf("decode queued report: %w", err)
	}
	return item, true, nil
}

func (q *ReportQueue) Ack(id string) error {
	q.mu.Lock()
	defer q.mu.Unlock()
	lines, err := q.readLocked()
	if err != nil {
		return err
	}
	filtered := make([][]byte, 0, len(lines))
	removed := false
	for _, line := range lines {
		var item queuedReport
		if err := json.Unmarshal(bytes.TrimSpace(line), &item); err != nil {
			return fmt.Errorf("decode queued report: %w", err)
		}
		if !removed && item.ID == id {
			removed = true
			continue
		}
		filtered = append(filtered, line)
	}
	if !removed {
		return fmt.Errorf("queued report %q was not found during acknowledgement", id)
	}
	return q.writeLocked(filtered)
}

func (q *ReportQueue) readLocked() ([][]byte, error) {
	file, err := os.Open(q.path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("open report queue: %w", err)
	}
	defer file.Close()
	var lines [][]byte
	scanner := bufio.NewScanner(file)
	scanner.Buffer(make([]byte, 64*1024), int(q.maxBytes)+1)
	for scanner.Scan() {
		line := append([]byte(nil), scanner.Bytes()...)
		if len(strings.TrimSpace(string(line))) != 0 {
			lines = append(lines, append(line, '\n'))
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("read report queue: %w", err)
	}
	return lines, nil
}

func (q *ReportQueue) writeLocked(lines [][]byte) error {
	directory := filepath.Dir(q.path)
	if err := os.MkdirAll(directory, 0o700); err != nil {
		return fmt.Errorf("create report queue directory: %w", err)
	}
	stale, _ := filepath.Glob(filepath.Join(directory, ".hostsentry-queue-*.tmp"))
	for _, name := range stale {
		_ = os.Remove(name)
	}
	tmp, err := os.CreateTemp(directory, ".hostsentry-queue-*.tmp")
	if err != nil {
		return fmt.Errorf("create report queue temp file: %w", err)
	}
	tmpPath := tmp.Name()
	defer os.Remove(tmpPath)
	if err := tmp.Chmod(0o600); err != nil {
		tmp.Close()
		return fmt.Errorf("secure report queue: %w", err)
	}
	for _, line := range lines {
		if _, err := tmp.Write(line); err != nil {
			tmp.Close()
			return fmt.Errorf("write report queue: %w", err)
		}
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return fmt.Errorf("sync report queue: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("close report queue: %w", err)
	}
	if err := os.Rename(tmpPath, q.path); err != nil {
		return fmt.Errorf("publish report queue: %w", err)
	}
	if dir, err := os.Open(directory); err == nil {
		defer dir.Close()
		if err := dir.Sync(); err != nil {
			return fmt.Errorf("sync report queue directory: %w", err)
		}
	}
	return nil
}
