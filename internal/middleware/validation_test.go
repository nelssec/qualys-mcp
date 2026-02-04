package middleware

import (
	"context"
	"testing"

	"github.com/nelssec/qualys-mcp/internal/domain"
)

func TestValidator_QQL(t *testing.T) {
	v := NewValidator(true)

	tests := []struct {
		name    string
		query   string
		wantErr bool
	}{
		{"valid simple", "severity:5", false},
		{"valid complex", "vulnerabilities.severity:5 and repo:nginx", false},
		{"valid with quotes", `name:"my app"`, false},
		{"sql injection attempt", "test; DROP TABLE hosts;--", true},
		{"script injection", "<script>alert(1)</script>", true},
		{"too long", string(make([]byte, 2001)), true},
		{"empty", "", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := &domain.ToolRequest{
				ID:   "test",
				Tool: "test_tool",
				Arguments: map[string]interface{}{
					"query": tt.query,
				},
			}

			middleware := v.Middleware()
			handler := func(ctx context.Context, req *domain.ToolRequest) (*domain.ToolResponse, error) {
				return &domain.ToolResponse{ID: req.ID, Success: true}, nil
			}

			resp, _ := middleware(handler)(context.Background(), req)

			if tt.wantErr && (resp.Error == nil) {
				t.Errorf("expected error for query %q, got none", tt.query)
			}
			if !tt.wantErr && (resp.Error != nil) {
				t.Errorf("unexpected error for query %q: %v", tt.query, resp.Error)
			}
		})
	}
}

func TestValidator_CVE(t *testing.T) {
	v := NewValidator(true)

	tests := []struct {
		name    string
		cve     string
		wantErr bool
	}{
		{"valid", "CVE-2021-44228", false},
		{"valid lowercase", "cve-2021-44228", false},
		{"valid long number", "CVE-2021-1234567", false},
		{"invalid format", "CVE2021-44228", true},
		{"invalid year", "CVE-21-44228", true},
		{"empty", "", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := &domain.ToolRequest{
				ID:   "test",
				Tool: "kb_get_cve_mapping",
				Arguments: map[string]interface{}{
					"cve": tt.cve,
				},
			}

			middleware := v.Middleware()
			handler := func(ctx context.Context, req *domain.ToolRequest) (*domain.ToolResponse, error) {
				return &domain.ToolResponse{ID: req.ID, Success: true}, nil
			}

			resp, _ := middleware(handler)(context.Background(), req)

			if tt.wantErr && (resp.Error == nil) {
				t.Errorf("expected error for CVE %q, got none", tt.cve)
			}
			if !tt.wantErr && (resp.Error != nil) {
				t.Errorf("unexpected error for CVE %q: %v", tt.cve, resp.Error)
			}
		})
	}
}

func TestValidator_ImageID(t *testing.T) {
	v := NewValidator(true)

	tests := []struct {
		name    string
		imageID string
		wantErr bool
	}{
		{"valid sha256 prefix", "sha256:abc123def456", false},
		{"valid no prefix", "abc123def456789012345678901234567890123456789012345678901234", false},
		{"valid short", "abc123def456", false},
		{"invalid chars", "sha256:xyz!@#", true},
		{"too short", "abc", true},
		{"empty", "", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := &domain.ToolRequest{
				ID:   "test",
				Tool: "cs_get_image_vulnerabilities",
				Arguments: map[string]interface{}{
					"image_id": tt.imageID,
				},
			}

			middleware := v.Middleware()
			handler := func(ctx context.Context, req *domain.ToolRequest) (*domain.ToolResponse, error) {
				return &domain.ToolResponse{ID: req.ID, Success: true}, nil
			}

			resp, _ := middleware(handler)(context.Background(), req)

			if tt.wantErr && (resp.Error == nil) {
				t.Errorf("expected error for image_id %q, got none", tt.imageID)
			}
			if !tt.wantErr && (resp.Error != nil) {
				t.Errorf("unexpected error for image_id %q: %v", tt.imageID, resp.Error)
			}
		})
	}
}

func TestValidator_Limit(t *testing.T) {
	v := NewValidator(true)

	tests := []struct {
		name    string
		limit   float64
		wantErr bool
	}{
		{"valid", 100, false},
		{"zero", 0, false},
		{"max", 10000, false},
		{"negative", -1, true},
		{"too large", 10001, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := &domain.ToolRequest{
				ID:   "test",
				Tool: "test_tool",
				Arguments: map[string]interface{}{
					"limit": tt.limit,
				},
			}

			middleware := v.Middleware()
			handler := func(ctx context.Context, req *domain.ToolRequest) (*domain.ToolResponse, error) {
				return &domain.ToolResponse{ID: req.ID, Success: true}, nil
			}

			resp, _ := middleware(handler)(context.Background(), req)

			if tt.wantErr && (resp.Error == nil) {
				t.Errorf("expected error for limit %v, got none", tt.limit)
			}
			if !tt.wantErr && (resp.Error != nil) {
				t.Errorf("unexpected error for limit %v: %v", tt.limit, resp.Error)
			}
		})
	}
}
