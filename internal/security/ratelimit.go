package security

import (
	"fmt"
	"sync"
	"time"
)

type RateLimiter struct {
	mu          sync.Mutex
	requests    []time.Time
	maxRequests int
	window      time.Duration
}

func NewRateLimiter(maxRequests int, window time.Duration) *RateLimiter {
	return &RateLimiter{
		requests:    make([]time.Time, 0),
		maxRequests: maxRequests,
		window:      window,
	}
}

func (r *RateLimiter) Allow() bool {
	r.mu.Lock()
	defer r.mu.Unlock()

	now := time.Now()
	cutoff := now.Add(-r.window)

	valid := make([]time.Time, 0)
	for _, t := range r.requests {
		if t.After(cutoff) {
			valid = append(valid, t)
		}
	}
	r.requests = valid

	if len(r.requests) >= r.maxRequests {
		return false
	}

	r.requests = append(r.requests, now)
	return true
}

func (r *RateLimiter) WaitTime() time.Duration {
	r.mu.Lock()
	defer r.mu.Unlock()

	if len(r.requests) < r.maxRequests {
		return 0
	}

	oldest := r.requests[0]
	return time.Until(oldest.Add(r.window))
}

type RateLimitError struct {
	RetryAfter time.Duration
}

func (e RateLimitError) Error() string {
	return fmt.Sprintf("rate limit exceeded, retry after %v", e.RetryAfter)
}

var DefaultRateLimiter = NewRateLimiter(100, time.Minute)

func CheckRateLimit() error {
	if !DefaultRateLimiter.Allow() {
		return RateLimitError{RetryAfter: DefaultRateLimiter.WaitTime()}
	}
	return nil
}
