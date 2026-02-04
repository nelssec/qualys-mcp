package domain

import (
	"context"
	"time"
)

type Severity int

const (
	SeverityInfo     Severity = 1
	SeverityLow      Severity = 2
	SeverityMedium   Severity = 3
	SeverityHigh     Severity = 4
	SeverityCritical Severity = 5
)

func (s Severity) String() string {
	switch s {
	case SeverityInfo:
		return "Info"
	case SeverityLow:
		return "Low"
	case SeverityMedium:
		return "Medium"
	case SeverityHigh:
		return "High"
	case SeverityCritical:
		return "Critical"
	default:
		return "Unknown"
	}
}

type ToolRequest struct {
	ID        string
	Tool      string
	Arguments map[string]interface{}
	User      *User
	Timestamp time.Time
}

type ToolResponse struct {
	ID        string
	Success   bool
	Data      interface{}
	Error     error
	Duration  time.Duration
	Timestamp time.Time
}

type User struct {
	ID       string
	Username string
	Email    string
	Roles    []string
	Claims   map[string]interface{}
}

func (u *User) HasRole(role string) bool {
	for _, r := range u.Roles {
		if r == role {
			return true
		}
	}
	return false
}

type ToolHandler func(ctx context.Context, req *ToolRequest) (*ToolResponse, error)

type Middleware func(ToolHandler) ToolHandler

type ToolRegistry interface {
	Register(name string, handler ToolHandler, middlewares ...Middleware)
	Get(name string) (ToolHandler, bool)
	List() []string
}
