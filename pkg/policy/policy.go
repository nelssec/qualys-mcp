package policy

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"

	"github.com/nelssec/qualys-mcp/internal/domain"
)

type Policy struct {
	Name         string            `json:"name"`
	Description  string            `json:"description,omitempty"`
	AllowedTools []string          `json:"allowed_tools,omitempty"`
	DeniedTools  []string          `json:"denied_tools,omitempty"`
	RateLimit    int               `json:"rate_limit_per_min,omitempty"`
	ArgFilters   map[string]Filter `json:"arg_filters,omitempty"`
}

type Filter struct {
	Pattern   string `json:"pattern,omitempty"`
	MaxLength int    `json:"max_length,omitempty"`
	Deny      bool   `json:"deny,omitempty"`
}

type RoleBinding struct {
	Role     string   `json:"role"`
	Policies []string `json:"policies"`
}

type UserPolicy struct {
	UserID   string   `json:"user_id,omitempty"`
	Username string   `json:"username,omitempty"`
	Roles    []string `json:"roles"`
}

type PolicyConfig struct {
	Policies     map[string]Policy  `json:"policies"`
	RoleBindings map[string][]string `json:"role_bindings"`
	Users        []UserPolicy       `json:"users,omitempty"`
	DefaultPolicy string            `json:"default_policy,omitempty"`
}

type Engine struct {
	mu       sync.RWMutex
	config   PolicyConfig
	compiled map[string]*compiledPolicy
}

type compiledPolicy struct {
	policy       Policy
	allowedRegex []*regexp.Regexp
	deniedRegex  []*regexp.Regexp
	argFilters   map[string]*regexp.Regexp
}

func NewEngine() *Engine {
	return &Engine{
		compiled: make(map[string]*compiledPolicy),
	}
}

func (e *Engine) LoadFromFile(path string) error {
	cleanPath := filepath.Clean(path)
	if strings.Contains(cleanPath, "..") {
		return fmt.Errorf("invalid path: path traversal detected")
	}

	data, err := os.ReadFile(cleanPath) // #nosec G304 - path is validated above
	if err != nil {
		return fmt.Errorf("read policy file: %w", err)
	}

	return e.LoadFromJSON(data)
}

func (e *Engine) LoadFromJSON(data []byte) error {
	var config PolicyConfig
	if err := json.Unmarshal(data, &config); err != nil {
		return fmt.Errorf("parse policy config: %w", err)
	}

	e.mu.Lock()
	defer e.mu.Unlock()

	e.config = config
	e.compiled = make(map[string]*compiledPolicy)

	for name, policy := range config.Policies {
		compiled, err := compilePolicy(policy)
		if err != nil {
			return fmt.Errorf("compile policy %s: %w", name, err)
		}
		e.compiled[name] = compiled
	}

	return nil
}

func compilePolicy(p Policy) (*compiledPolicy, error) {
	cp := &compiledPolicy{
		policy:     p,
		argFilters: make(map[string]*regexp.Regexp),
	}

	for _, pattern := range p.AllowedTools {
		if pattern == "*" {
			cp.allowedRegex = append(cp.allowedRegex, regexp.MustCompile(".*"))
		} else {
			re, err := regexp.Compile("^" + regexp.QuoteMeta(pattern) + "$")
			if err != nil {
				return nil, fmt.Errorf("invalid allowed pattern %s: %w", pattern, err)
			}
			cp.allowedRegex = append(cp.allowedRegex, re)
		}
	}

	for _, pattern := range p.DeniedTools {
		if pattern == "*" {
			cp.deniedRegex = append(cp.deniedRegex, regexp.MustCompile(".*"))
		} else {
			re, err := regexp.Compile("^" + regexp.QuoteMeta(pattern) + "$")
			if err != nil {
				return nil, fmt.Errorf("invalid denied pattern %s: %w", pattern, err)
			}
			cp.deniedRegex = append(cp.deniedRegex, re)
		}
	}

	for arg, filter := range p.ArgFilters {
		if filter.Pattern != "" {
			re, err := regexp.Compile(filter.Pattern)
			if err != nil {
				return nil, fmt.Errorf("invalid arg filter pattern for %s: %w", arg, err)
			}
			cp.argFilters[arg] = re
		}
	}

	return cp, nil
}

func (e *Engine) Evaluate(ctx context.Context, user *domain.User, tool string, args map[string]interface{}) error {
	e.mu.RLock()
	defer e.mu.RUnlock()

	policies := e.getPoliciesForUser(user)
	if len(policies) == 0 {
		if e.config.DefaultPolicy != "" {
			if cp, ok := e.compiled[e.config.DefaultPolicy]; ok {
				policies = []*compiledPolicy{cp}
			}
		}
	}

	if len(policies) == 0 {
		return domain.NewForbiddenError("no policies apply to user")
	}

	for _, cp := range policies {
		if err := e.evaluatePolicy(cp, tool, args); err != nil {
			return err
		}
	}

	return nil
}

func (e *Engine) getPoliciesForUser(user *domain.User) []*compiledPolicy {
	var policies []*compiledPolicy

	if user == nil {
		return policies
	}

	for _, role := range user.Roles {
		if policyNames, ok := e.config.RoleBindings[role]; ok {
			for _, name := range policyNames {
				if cp, ok := e.compiled[name]; ok {
					policies = append(policies, cp)
				}
			}
		}
	}

	return policies
}

func (e *Engine) evaluatePolicy(cp *compiledPolicy, tool string, args map[string]interface{}) error {
	for _, re := range cp.deniedRegex {
		if re.MatchString(tool) {
			return domain.NewForbiddenError(fmt.Sprintf("tool %s denied by policy %s", tool, cp.policy.Name))
		}
	}

	if len(cp.allowedRegex) > 0 {
		allowed := false
		for _, re := range cp.allowedRegex {
			if re.MatchString(tool) {
				allowed = true
				break
			}
		}
		if !allowed {
			return domain.NewForbiddenError(fmt.Sprintf("tool %s not allowed by policy %s", tool, cp.policy.Name))
		}
	}

	for argName, re := range cp.argFilters {
		if val, ok := args[argName]; ok {
			strVal, isString := val.(string)
			if isString {
				filter := cp.policy.ArgFilters[argName]
				if filter.Deny && re.MatchString(strVal) {
					return domain.NewForbiddenError(fmt.Sprintf("argument %s contains denied pattern", argName))
				}
				if !filter.Deny && !re.MatchString(strVal) {
					return domain.NewForbiddenError(fmt.Sprintf("argument %s does not match required pattern", argName))
				}
				if filter.MaxLength > 0 && len(strVal) > filter.MaxLength {
					return domain.NewForbiddenError(fmt.Sprintf("argument %s exceeds max length %d", argName, filter.MaxLength))
				}
			}
		}
	}

	return nil
}

func (e *Engine) GetRateLimit(user *domain.User) int {
	e.mu.RLock()
	defer e.mu.RUnlock()

	maxLimit := 0
	policies := e.getPoliciesForUser(user)

	for _, cp := range policies {
		if cp.policy.RateLimit > maxLimit {
			maxLimit = cp.policy.RateLimit
		}
	}

	if maxLimit == 0 && e.config.DefaultPolicy != "" {
		if cp, ok := e.compiled[e.config.DefaultPolicy]; ok {
			maxLimit = cp.policy.RateLimit
		}
	}

	return maxLimit
}

func (e *Engine) Middleware() domain.Middleware {
	return func(next domain.ToolHandler) domain.ToolHandler {
		return func(ctx context.Context, req *domain.ToolRequest) (*domain.ToolResponse, error) {
			if err := e.Evaluate(ctx, req.User, req.Tool, req.Arguments); err != nil {
				return &domain.ToolResponse{
					ID:      req.ID,
					Success: false,
					Error:   err,
				}, nil
			}
			return next(ctx, req)
		}
	}
}
