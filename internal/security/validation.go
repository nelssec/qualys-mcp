package security

import (
	"fmt"
	"regexp"
	"strings"
)

var (
	dangerousPatterns = []*regexp.Regexp{
		regexp.MustCompile(`(?i)(;|--|drop|delete|truncate|update|insert|exec|execute)`),
		regexp.MustCompile(`(?i)<script`),
		regexp.MustCompile(`(?i)javascript:`),
	}

	validQQLPattern = regexp.MustCompile(`^[a-zA-Z0-9_\-\.\:\s\(\)\[\]\*\"\'\=\<\>\!\&\|,/]+$`)
)

type ValidationError struct {
	Field   string
	Message string
}

func (e ValidationError) Error() string {
	return fmt.Sprintf("validation error on %s: %s", e.Field, e.Message)
}

func ValidateQQL(query string) error {
	if query == "" {
		return nil
	}

	if len(query) > 2000 {
		return ValidationError{Field: "query", Message: "query exceeds maximum length of 2000 characters"}
	}

	for _, pattern := range dangerousPatterns {
		if pattern.MatchString(query) {
			return ValidationError{Field: "query", Message: "query contains potentially dangerous patterns"}
		}
	}

	if !validQQLPattern.MatchString(query) {
		return ValidationError{Field: "query", Message: "query contains invalid characters"}
	}

	return nil
}

func ValidateHostID(hostID string) error {
	if hostID == "" {
		return ValidationError{Field: "host_id", Message: "host_id is required"}
	}

	if len(hostID) > 100 {
		return ValidationError{Field: "host_id", Message: "host_id exceeds maximum length"}
	}

	if strings.ContainsAny(hostID, ";<>\"'") {
		return ValidationError{Field: "host_id", Message: "host_id contains invalid characters"}
	}

	return nil
}

func ValidateImageID(imageID string) error {
	if imageID == "" {
		return ValidationError{Field: "image_id", Message: "image_id is required"}
	}

	validSHA := regexp.MustCompile(`^(sha256:)?[a-fA-F0-9]{12,64}$`)
	if !validSHA.MatchString(imageID) {
		return ValidationError{Field: "image_id", Message: "image_id must be a valid SHA256 hash"}
	}

	return nil
}

func ValidateCVE(cve string) error {
	if cve == "" {
		return ValidationError{Field: "cve", Message: "cve is required"}
	}

	validCVE := regexp.MustCompile(`^CVE-\d{4}-\d{4,}$`)
	if !validCVE.MatchString(strings.ToUpper(cve)) {
		return ValidationError{Field: "cve", Message: "cve must be in format CVE-YYYY-NNNNN"}
	}

	return nil
}

func ValidateLimit(limit int) error {
	if limit < 0 {
		return ValidationError{Field: "limit", Message: "limit cannot be negative"}
	}
	if limit > 10000 {
		return ValidationError{Field: "limit", Message: "limit cannot exceed 10000"}
	}
	return nil
}

func SanitizeString(s string) string {
	s = strings.ReplaceAll(s, "<", "&lt;")
	s = strings.ReplaceAll(s, ">", "&gt;")
	s = strings.ReplaceAll(s, "\"", "&quot;")
	return s
}
