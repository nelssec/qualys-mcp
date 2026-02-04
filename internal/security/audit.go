package security

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

type AuditEvent struct {
	Timestamp  time.Time              `json:"timestamp"`
	Tool       string                 `json:"tool"`
	Arguments  map[string]interface{} `json:"arguments,omitempty"`
	Success    bool                   `json:"success"`
	Error      string                 `json:"error,omitempty"`
	DurationMs int64                  `json:"duration_ms"`
	UserAgent  string                 `json:"user_agent,omitempty"`
}

type AuditLogger struct {
	mu      sync.Mutex
	writer  io.Writer
	enabled bool
}

func NewAuditLogger(logPath string) (*AuditLogger, error) {
	if logPath == "" {
		return &AuditLogger{enabled: false}, nil
	}

	cleanPath := filepath.Clean(logPath)
	if strings.Contains(cleanPath, "..") {
		return nil, fmt.Errorf("invalid path: path traversal detected")
	}

	f, err := os.OpenFile(cleanPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0600) // #nosec G304 - path validated
	if err != nil {
		return nil, fmt.Errorf("open audit log: %w", err)
	}

	return &AuditLogger{
		writer:  f,
		enabled: true,
	}, nil
}

func (a *AuditLogger) Log(ctx context.Context, event AuditEvent) {
	if !a.enabled {
		return
	}

	a.mu.Lock()
	defer a.mu.Unlock()

	event.Timestamp = time.Now().UTC()
	data, _ := json.Marshal(event)
	fmt.Fprintln(a.writer, string(data))
}

func (a *AuditLogger) LogToolCall(tool string, args map[string]interface{}, err error, duration time.Duration) {
	event := AuditEvent{
		Tool:       tool,
		Arguments:  a.sanitizeArgs(args),
		Success:    err == nil,
		DurationMs: duration.Milliseconds(),
	}
	if err != nil {
		event.Error = err.Error()
	}
	a.Log(context.Background(), event)
}

func (a *AuditLogger) sanitizeArgs(args map[string]interface{}) map[string]interface{} {
	sanitized := make(map[string]interface{})
	for k, v := range args {
		if k == "password" || k == "token" || k == "secret" {
			sanitized[k] = "[REDACTED]"
		} else {
			sanitized[k] = v
		}
	}
	return sanitized
}
