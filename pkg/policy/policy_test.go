package policy

import (
	"context"
	"testing"

	"github.com/nelssec/qualys-mcp/internal/domain"
)

func TestEngine_Evaluate(t *testing.T) {
	configJSON := `{
		"policies": {
			"admin": {
				"name": "admin",
				"allowed_tools": ["*"],
				"rate_limit_per_min": 1000
			},
			"analyst": {
				"name": "analyst",
				"allowed_tools": ["vmdr_list_hosts", "kb_search_vulns"],
				"denied_tools": ["vmdr_search_detections"],
				"rate_limit_per_min": 100
			},
			"deny-all": {
				"name": "deny-all",
				"denied_tools": ["*"]
			}
		},
		"role_bindings": {
			"security-admin": ["admin"],
			"security-analyst": ["analyst"],
			"anonymous": ["deny-all"]
		},
		"default_policy": "deny-all"
	}`

	engine := NewEngine()
	if err := engine.LoadFromJSON([]byte(configJSON)); err != nil {
		t.Fatalf("Failed to load config: %v", err)
	}

	tests := []struct {
		name    string
		user    *domain.User
		tool    string
		wantErr bool
	}{
		{
			name:    "admin can access anything",
			user:    &domain.User{ID: "1", Roles: []string{"security-admin"}},
			tool:    "vmdr_search_detections",
			wantErr: false,
		},
		{
			name:    "analyst can access allowed tool",
			user:    &domain.User{ID: "2", Roles: []string{"security-analyst"}},
			tool:    "vmdr_list_hosts",
			wantErr: false,
		},
		{
			name:    "analyst denied specific tool",
			user:    &domain.User{ID: "2", Roles: []string{"security-analyst"}},
			tool:    "vmdr_search_detections",
			wantErr: true,
		},
		{
			name:    "analyst denied unlisted tool",
			user:    &domain.User{ID: "2", Roles: []string{"security-analyst"}},
			tool:    "cs_list_images",
			wantErr: true,
		},
		{
			name:    "anonymous denied everything",
			user:    &domain.User{ID: "3", Roles: []string{"anonymous"}},
			tool:    "kb_search_vulns",
			wantErr: true,
		},
		{
			name:    "unknown user gets default deny",
			user:    &domain.User{ID: "4", Roles: []string{"unknown-role"}},
			tool:    "anything",
			wantErr: true,
		},
		{
			name:    "nil user gets default deny",
			user:    nil,
			tool:    "anything",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := engine.Evaluate(context.Background(), tt.user, tt.tool, nil)
			if tt.wantErr && err == nil {
				t.Errorf("expected error, got none")
			}
			if !tt.wantErr && err != nil {
				t.Errorf("unexpected error: %v", err)
			}
		})
	}
}

func TestEngine_GetRateLimit(t *testing.T) {
	configJSON := `{
		"policies": {
			"admin": {
				"name": "admin",
				"allowed_tools": ["*"],
				"rate_limit_per_min": 1000
			},
			"analyst": {
				"name": "analyst",
				"allowed_tools": ["*"],
				"rate_limit_per_min": 100
			}
		},
		"role_bindings": {
			"security-admin": ["admin"],
			"security-analyst": ["analyst"]
		},
		"default_policy": "analyst"
	}`

	engine := NewEngine()
	if err := engine.LoadFromJSON([]byte(configJSON)); err != nil {
		t.Fatalf("Failed to load config: %v", err)
	}

	tests := []struct {
		name     string
		user     *domain.User
		expected int
	}{
		{
			name:     "admin gets high limit",
			user:     &domain.User{ID: "1", Roles: []string{"security-admin"}},
			expected: 1000,
		},
		{
			name:     "analyst gets lower limit",
			user:     &domain.User{ID: "2", Roles: []string{"security-analyst"}},
			expected: 100,
		},
		{
			name:     "unknown gets default",
			user:     &domain.User{ID: "3", Roles: []string{"unknown"}},
			expected: 100,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			limit := engine.GetRateLimit(tt.user)
			if limit != tt.expected {
				t.Errorf("expected rate limit %d, got %d", tt.expected, limit)
			}
		})
	}
}

func TestEngine_ArgFilters(t *testing.T) {
	configJSON := `{
		"policies": {
			"filtered": {
				"name": "filtered",
				"allowed_tools": ["*"],
				"arg_filters": {
					"query": {
						"pattern": "^[a-z]+$",
						"max_length": 10
					},
					"dangerous": {
						"pattern": "admin",
						"deny": true
					}
				}
			}
		},
		"role_bindings": {
			"user": ["filtered"]
		}
	}`

	engine := NewEngine()
	if err := engine.LoadFromJSON([]byte(configJSON)); err != nil {
		t.Fatalf("Failed to load config: %v", err)
	}

	tests := []struct {
		name    string
		args    map[string]interface{}
		wantErr bool
	}{
		{
			name:    "valid query",
			args:    map[string]interface{}{"query": "test"},
			wantErr: false,
		},
		{
			name:    "query too long",
			args:    map[string]interface{}{"query": "verylongquery"},
			wantErr: true,
		},
		{
			name:    "query wrong pattern",
			args:    map[string]interface{}{"query": "TEST123"},
			wantErr: true,
		},
		{
			name:    "denied pattern",
			args:    map[string]interface{}{"dangerous": "admin"},
			wantErr: true,
		},
		{
			name:    "allowed value",
			args:    map[string]interface{}{"dangerous": "user"},
			wantErr: false,
		},
	}

	user := &domain.User{ID: "1", Roles: []string{"user"}}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := engine.Evaluate(context.Background(), user, "test_tool", tt.args)
			if tt.wantErr && err == nil {
				t.Errorf("expected error, got none")
			}
			if !tt.wantErr && err != nil {
				t.Errorf("unexpected error: %v", err)
			}
		})
	}
}
