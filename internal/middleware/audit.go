package middleware

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

	"github.com/nelssec/qualys-mcp/internal/domain"
)

type AuditEntry struct {
	Timestamp  time.Time              `json:"timestamp"`
	RequestID  string                 `json:"request_id"`
	UserID     string                 `json:"user_id,omitempty"`
	Username   string                 `json:"username,omitempty"`
	Tool       string                 `json:"tool"`
	Arguments  map[string]interface{} `json:"arguments,omitempty"`
	Success    bool                   `json:"success"`
	Error      string                 `json:"error,omitempty"`
	DurationMs int64                  `json:"duration_ms"`
}

type AuditLogger struct {
	mu      sync.Mutex
	writer  io.Writer
	closer  io.Closer
	enabled bool
}

func NewAuditLogger(path string) (*AuditLogger, error) {
	if path == "" {
		return &AuditLogger{enabled: false}, nil
	}

	cleanPath := filepath.Clean(path)
	if strings.Contains(cleanPath, "..") {
		return nil, fmt.Errorf("invalid path: path traversal detected")
	}

	f, err := os.OpenFile(cleanPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0600) // #nosec G304 - path validated
	if err != nil {
		return nil, fmt.Errorf("open audit log %s: %w", cleanPath, err)
	}

	return &AuditLogger{
		writer:  f,
		closer:  f,
		enabled: true,
	}, nil
}

func (a *AuditLogger) Close() error {
	if a.closer != nil {
		return a.closer.Close()
	}
	return nil
}

func (a *AuditLogger) write(entry AuditEntry) {
	if !a.enabled {
		return
	}

	a.mu.Lock()
	defer a.mu.Unlock()

	data, err := json.Marshal(entry)
	if err != nil {
		return
	}

	fmt.Fprintln(a.writer, string(data))
}

func (a *AuditLogger) Middleware() domain.Middleware {
	return func(next domain.ToolHandler) domain.ToolHandler {
		return func(ctx context.Context, req *domain.ToolRequest) (*domain.ToolResponse, error) {
			start := time.Now()

			resp, err := next(ctx, req)

			duration := time.Since(start)

			entry := AuditEntry{
				Timestamp:  time.Now().UTC(),
				RequestID:  req.ID,
				Tool:       req.Tool,
				Arguments:  sanitizeArgsForAudit(req.Arguments),
				Success:    err == nil && (resp == nil || resp.Error == nil),
				DurationMs: duration.Milliseconds(),
			}

			if req.User != nil {
				entry.UserID = req.User.ID
				entry.Username = req.User.Username
			}

			if err != nil {
				entry.Error = err.Error()
			} else if resp != nil && resp.Error != nil {
				entry.Error = resp.Error.Error()
			}

			a.write(entry)

			return resp, err
		}
	}
}

func sanitizeArgsForAudit(args map[string]interface{}) map[string]interface{} {
	sensitiveKeys := map[string]bool{
		"password":    true,
		"token":       true,
		"secret":      true,
		"key":         true,
		"api_key":     true,
		"apikey":      true,
		"credentials": true,
		"auth":        true,
	}

	sanitized := make(map[string]interface{})
	for k, v := range args {
		if sensitiveKeys[k] {
			sanitized[k] = "[REDACTED]"
		} else {
			sanitized[k] = v
		}
	}
	return sanitized
}
