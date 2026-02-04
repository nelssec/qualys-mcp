package logging

import (
	"context"
	"io"
	"log/slog"
	"os"
	"runtime"
	"time"

	"github.com/nelssec/qualys-mcp/internal/domain"
)

type Logger struct {
	*slog.Logger
}

type Config struct {
	Level      slog.Level
	Format     string
	Output     io.Writer
	AddSource  bool
	TimeFormat string
}

func DefaultConfig() Config {
	return Config{
		Level:      slog.LevelInfo,
		Format:     "json",
		Output:     os.Stderr,
		AddSource:  false,
		TimeFormat: time.RFC3339,
	}
}

func New(cfg Config) *Logger {
	var handler slog.Handler

	opts := &slog.HandlerOptions{
		Level:     cfg.Level,
		AddSource: cfg.AddSource,
	}

	if cfg.Format == "text" {
		handler = slog.NewTextHandler(cfg.Output, opts)
	} else {
		handler = slog.NewJSONHandler(cfg.Output, opts)
	}

	return &Logger{
		Logger: slog.New(handler),
	}
}

func (l *Logger) WithRequestID(requestID string) *Logger {
	return &Logger{
		Logger: l.Logger.With("request_id", requestID),
	}
}

func (l *Logger) WithUser(user *domain.User) *Logger {
	if user == nil {
		return l
	}
	return &Logger{
		Logger: l.Logger.With(
			"user_id", user.ID,
			"username", user.Username,
		),
	}
}

func (l *Logger) WithTool(toolName string) *Logger {
	return &Logger{
		Logger: l.Logger.With("tool", toolName),
	}
}

func (l *Logger) WithError(err error) *Logger {
	return &Logger{
		Logger: l.Logger.With("error", err.Error()),
	}
}

func (l *Logger) WithDuration(d time.Duration) *Logger {
	return &Logger{
		Logger: l.Logger.With("duration_ms", d.Milliseconds()),
	}
}

func (l *Logger) ToolCall(ctx context.Context, tool string, args map[string]interface{}) {
	l.Logger.InfoContext(ctx, "tool_call_started",
		"tool", tool,
		"args", sanitizeArgs(args),
	)
}

func (l *Logger) ToolComplete(ctx context.Context, tool string, duration time.Duration, err error) {
	if err != nil {
		l.Logger.ErrorContext(ctx, "tool_call_failed",
			"tool", tool,
			"duration_ms", duration.Milliseconds(),
			"error", err.Error(),
		)
	} else {
		l.Logger.InfoContext(ctx, "tool_call_completed",
			"tool", tool,
			"duration_ms", duration.Milliseconds(),
		)
	}
}

func (l *Logger) AuthSuccess(ctx context.Context, userID string) {
	l.Logger.InfoContext(ctx, "auth_success", "user_id", userID)
}

func (l *Logger) AuthFailure(ctx context.Context, reason string) {
	l.Logger.WarnContext(ctx, "auth_failure", "reason", reason)
}

func (l *Logger) RateLimited(ctx context.Context, userID string) {
	l.Logger.WarnContext(ctx, "rate_limited", "user_id", userID)
}

func (l *Logger) PolicyDenied(ctx context.Context, userID, tool, reason string) {
	l.Logger.WarnContext(ctx, "policy_denied",
		"user_id", userID,
		"tool", tool,
		"reason", reason,
	)
}

func (l *Logger) Panic(ctx context.Context, recovered interface{}) {
	stack := make([]byte, 4096)
	n := runtime.Stack(stack, false)

	l.Logger.ErrorContext(ctx, "panic_recovered",
		"panic", recovered,
		"stack", string(stack[:n]),
	)
}

func sanitizeArgs(args map[string]interface{}) map[string]interface{} {
	sensitiveKeys := map[string]bool{
		"password": true,
		"token":    true,
		"secret":   true,
		"key":      true,
		"api_key":  true,
		"apikey":   true,
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

var defaultLogger = New(DefaultConfig())

func Default() *Logger {
	return defaultLogger
}

func SetDefault(l *Logger) {
	defaultLogger = l
}
