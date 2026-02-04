package middleware

import (
	"context"
	"fmt"

	"github.com/nelssec/qualys-mcp/internal/domain"
	"github.com/nelssec/qualys-mcp/internal/logging"
)

func Recovery(logger *logging.Logger) domain.Middleware {
	return func(next domain.ToolHandler) domain.ToolHandler {
		return func(ctx context.Context, req *domain.ToolRequest) (resp *domain.ToolResponse, err error) {
			defer func() {
				if r := recover(); r != nil {
					logger.Panic(ctx, r)
					err = domain.NewError("PANIC", fmt.Sprintf("panic recovered: %v", r), domain.ErrInternal)
					resp = &domain.ToolResponse{
						ID:      req.ID,
						Success: false,
						Error:   err,
					}
				}
			}()

			return next(ctx, req)
		}
	}
}
