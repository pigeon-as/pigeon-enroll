// Package audit provides append-only JSONL audit logging.
// Follows the Vault audit log pattern: one JSON object per line, synced to
// disk after each write.
// Reference: https://developer.hashicorp.com/vault/docs/audit
package audit

import (
	"encoding/json"
	"os"
	"sync"
	"time"
)

// Entry is one audit log line.
type Entry struct {
	Timestamp string `json:"ts"`
	Operation string `json:"op"`
	IP        string `json:"ip"`
	Scope     string `json:"scope,omitempty"`
	OK        bool   `json:"ok"`
	Error     string `json:"error,omitempty"`
}

// Log is an append-only JSONL audit logger.
type Log struct {
	mu   sync.Mutex
	file *os.File
}

// Open opens (or creates) the audit log file for appending.
// Returns nil if path is empty (audit disabled).
func Open(path string) (*Log, error) {
	if path == "" {
		return nil, nil
	}
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0600)
	if err != nil {
		return nil, err
	}
	return &Log{file: f}, nil
}

// Record writes one audit entry as a JSON line.
func (l *Log) Record(e Entry) {
	if l == nil {
		return
	}
	if e.Timestamp == "" {
		e.Timestamp = time.Now().UTC().Format(time.RFC3339)
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	data, _ := json.Marshal(e)
	data = append(data, '\n')
	l.file.Write(data)
	l.file.Sync()
}

// Close closes the audit log file.
func (l *Log) Close() error {
	if l == nil {
		return nil
	}
	return l.file.Close()
}
