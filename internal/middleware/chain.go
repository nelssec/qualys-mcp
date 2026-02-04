package middleware

import (
	"context"

	"github.com/nelssec/qualys-mcp/internal/domain"
)

type Chain struct {
	middlewares []domain.Middleware
}

func NewChain(middlewares ...domain.Middleware) *Chain {
	return &Chain{
		middlewares: middlewares,
	}
}

func (c *Chain) Add(m domain.Middleware) *Chain {
	c.middlewares = append(c.middlewares, m)
	return c
}

func (c *Chain) Then(handler domain.ToolHandler) domain.ToolHandler {
	if len(c.middlewares) == 0 {
		return handler
	}

	wrapped := handler
	for i := len(c.middlewares) - 1; i >= 0; i-- {
		wrapped = c.middlewares[i](wrapped)
	}
	return wrapped
}

func (c *Chain) ThenFunc(fn func(ctx context.Context, req *domain.ToolRequest) (*domain.ToolResponse, error)) domain.ToolHandler {
	return c.Then(domain.ToolHandler(fn))
}
