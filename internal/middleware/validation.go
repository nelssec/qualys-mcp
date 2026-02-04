package middleware

import (
	"context"
	"fmt"
	"regexp"
	"strings"

	"github.com/nelssec/qualys-mcp/internal/domain"
)

type Validator struct {
	enabled bool
}

func NewValidator(enabled bool) *Validator {
	return &Validator{enabled: enabled}
}

var (
	dangerousPatterns = []*regexp.Regexp{
		regexp.MustCompile(`(?i)(;|--)\s*(drop|delete|truncate|update|insert|exec|execute)`),
		regexp.MustCompile(`(?i)<script[^>]*>`),
		regexp.MustCompile(`(?i)javascript\s*:`),
		regexp.MustCompile(`(?i)on\w+\s*=`),
	}

	validQQLPattern   = regexp.MustCompile(`^[a-zA-Z0-9_\-\.\:\s\(\)\[\]\*\"\'\=\<\>\!\&\|,/]+$`)
	validCVEPattern   = regexp.MustCompile(`^CVE-\d{4}-\d{4,}$`)
	validSHA256Pattern = regexp.MustCompile(`^(sha256:)?[a-fA-F0-9]{12,64}$`)
)

func (v *Validator) Middleware() domain.Middleware {
	return func(next domain.ToolHandler) domain.ToolHandler {
		return func(ctx context.Context, req *domain.ToolRequest) (*domain.ToolResponse, error) {
			if !v.enabled {
				return next(ctx, req)
			}

			if err := v.validateRequest(req); err != nil {
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

func (v *Validator) validateRequest(req *domain.ToolRequest) error {
	for key, value := range req.Arguments {
		strVal, ok := value.(string)
		if !ok {
			continue
		}

		if err := v.validateString(key, strVal); err != nil {
			return err
		}

		switch key {
		case "query", "filter", "qql":
			if err := v.validateQQL(strVal); err != nil {
				return err
			}
		case "cve":
			if err := v.validateCVE(strVal); err != nil {
				return err
			}
		case "image_id":
			if err := v.validateImageID(strVal); err != nil {
				return err
			}
		}
	}

	if limit, ok := req.Arguments["limit"].(float64); ok {
		if err := v.validateLimit(int(limit)); err != nil {
			return err
		}
	}

	return nil
}

func (v *Validator) validateString(field, value string) error {
	if len(value) > 10000 {
		return domain.NewValidationError(field, "value exceeds maximum length of 10000 characters")
	}

	for _, pattern := range dangerousPatterns {
		if pattern.MatchString(value) {
			return domain.NewValidationError(field, "value contains potentially dangerous patterns")
		}
	}

	return nil
}

func (v *Validator) validateQQL(query string) error {
	if query == "" {
		return nil
	}

	if len(query) > 2000 {
		return domain.NewValidationError("query", "QQL query exceeds maximum length of 2000 characters")
	}

	if !validQQLPattern.MatchString(query) {
		return domain.NewValidationError("query", "QQL query contains invalid characters")
	}

	return nil
}

func (v *Validator) validateCVE(cve string) error {
	if cve == "" {
		return nil
	}

	if !validCVEPattern.MatchString(strings.ToUpper(cve)) {
		return domain.NewValidationError("cve", "CVE must be in format CVE-YYYY-NNNNN")
	}

	return nil
}

func (v *Validator) validateImageID(imageID string) error {
	if imageID == "" {
		return nil
	}

	if !validSHA256Pattern.MatchString(imageID) {
		return domain.NewValidationError("image_id", "image_id must be a valid SHA256 hash")
	}

	return nil
}

func (v *Validator) validateLimit(limit int) error {
	if limit < 0 {
		return domain.NewValidationError("limit", "limit cannot be negative")
	}
	if limit > 10000 {
		return domain.NewValidationError("limit", fmt.Sprintf("limit cannot exceed 10000, got %d", limit))
	}
	return nil
}
