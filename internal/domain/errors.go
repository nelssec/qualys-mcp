package domain

import (
	"errors"
	"fmt"
)

var (
	ErrUnauthorized     = errors.New("unauthorized")
	ErrForbidden        = errors.New("forbidden")
	ErrNotFound         = errors.New("not found")
	ErrRateLimited      = errors.New("rate limited")
	ErrValidation       = errors.New("validation error")
	ErrInternal         = errors.New("internal error")
	ErrToolNotFound     = errors.New("tool not found")
	ErrInvalidArgument  = errors.New("invalid argument")
	ErrCredentialsError = errors.New("credentials error")
)

type Error struct {
	Code    string
	Message string
	Cause   error
	Details map[string]interface{}
}

func (e *Error) Error() string {
	if e.Cause != nil {
		return fmt.Sprintf("%s: %s: %v", e.Code, e.Message, e.Cause)
	}
	return fmt.Sprintf("%s: %s", e.Code, e.Message)
}

func (e *Error) Unwrap() error {
	return e.Cause
}

func NewError(code string, message string, cause error) *Error {
	return &Error{
		Code:    code,
		Message: message,
		Cause:   cause,
	}
}

func NewValidationError(field, message string) *Error {
	return &Error{
		Code:    "VALIDATION_ERROR",
		Message: message,
		Cause:   ErrValidation,
		Details: map[string]interface{}{
			"field": field,
		},
	}
}

func NewAuthError(message string) *Error {
	return &Error{
		Code:    "AUTH_ERROR",
		Message: message,
		Cause:   ErrUnauthorized,
	}
}

func NewForbiddenError(message string) *Error {
	return &Error{
		Code:    "FORBIDDEN",
		Message: message,
		Cause:   ErrForbidden,
	}
}

func NewRateLimitError(retryAfterSec int) *Error {
	return &Error{
		Code:    "RATE_LIMITED",
		Message: fmt.Sprintf("rate limit exceeded, retry after %d seconds", retryAfterSec),
		Cause:   ErrRateLimited,
		Details: map[string]interface{}{
			"retry_after_seconds": retryAfterSec,
		},
	}
}

func IsValidationError(err error) bool {
	return errors.Is(err, ErrValidation)
}

func IsAuthError(err error) bool {
	return errors.Is(err, ErrUnauthorized) || errors.Is(err, ErrForbidden)
}

func IsRateLimitError(err error) bool {
	return errors.Is(err, ErrRateLimited)
}
