package middleware

import (
	"context"
	"sync"
	"time"

	"github.com/nelssec/qualys-mcp/internal/domain"
	"github.com/nelssec/qualys-mcp/internal/logging"
)

type RateLimiter struct {
	mu          sync.Mutex
	requests    map[string][]time.Time
	maxRequests int
	window      time.Duration
	logger      *logging.Logger
}

func NewRateLimiter(maxRequests int, window time.Duration, logger *logging.Logger) *RateLimiter {
	return &RateLimiter{
		requests:    make(map[string][]time.Time),
		maxRequests: maxRequests,
		window:      window,
		logger:      logger,
	}
}

func (rl *RateLimiter) allow(userID string) (bool, int) {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	now := time.Now()
	cutoff := now.Add(-rl.window)

	requests := rl.requests[userID]
	valid := make([]time.Time, 0, len(requests))
	for _, t := range requests {
		if t.After(cutoff) {
			valid = append(valid, t)
		}
	}

	if len(valid) >= rl.maxRequests {
		oldest := valid[0]
		retryAfter := int(time.Until(oldest.Add(rl.window)).Seconds()) + 1
		rl.requests[userID] = valid
		return false, retryAfter
	}

	rl.requests[userID] = append(valid, now)
	return true, 0
}

func (rl *RateLimiter) Middleware() domain.Middleware {
	return func(next domain.ToolHandler) domain.ToolHandler {
		return func(ctx context.Context, req *domain.ToolRequest) (*domain.ToolResponse, error) {
			userID := "anonymous"
			if req.User != nil {
				userID = req.User.ID
			}

			allowed, retryAfter := rl.allow(userID)
			if !allowed {
				rl.logger.RateLimited(ctx, userID)
				return &domain.ToolResponse{
					ID:      req.ID,
					Success: false,
					Error:   domain.NewRateLimitError(retryAfter),
				}, nil
			}

			return next(ctx, req)
		}
	}
}
