package middleware

import (
	"context"
	"time"

	"github.com/nelssec/qualys-mcp/internal/domain"
	"github.com/nelssec/qualys-mcp/internal/logging"
)

func Logging(logger *logging.Logger) domain.Middleware {
	return func(next domain.ToolHandler) domain.ToolHandler {
		return func(ctx context.Context, req *domain.ToolRequest) (*domain.ToolResponse, error) {
			log := logger.WithRequestID(req.ID).WithTool(req.Tool)

			if req.User != nil {
				log = log.WithUser(req.User)
			}

			log.ToolCall(ctx, req.Tool, req.Arguments)

			start := time.Now()
			resp, err := next(ctx, req)
			duration := time.Since(start)

			if resp != nil {
				resp.Duration = duration
			}

			log.ToolComplete(ctx, req.Tool, duration, err)

			return resp, err
		}
	}
}
