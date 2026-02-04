package common

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/nelssec/qualys-mcp/internal/auth"
)

type HTTPClient struct {
	client   *http.Client
	tokenMgr *auth.TokenManager
}

func NewHTTPClient(tokenMgr *auth.TokenManager) *HTTPClient {
	return &HTTPClient{
		client: &http.Client{
			Timeout: 60 * time.Second,
		},
		tokenMgr: tokenMgr,
	}
}

func (c *HTTPClient) Do(ctx context.Context, req *http.Request) (*http.Response, error) {
	if err := c.tokenMgr.EnsureToken(ctx); err != nil {
		return nil, fmt.Errorf("ensure token: %w", err)
	}
	c.tokenMgr.ApplyAuth(req)
	req.Header.Set("X-Requested-With", "qualys-mcp")

	return c.client.Do(req)
}

func (c *HTTPClient) Get(ctx context.Context, url string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, fmt.Errorf("create request: %w", err)
	}

	resp, err := c.Do(ctx, req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read response: %w", err)
	}

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("API error (status %d): %s", resp.StatusCode, string(body))
	}

	return body, nil
}

func (c *HTTPClient) Post(ctx context.Context, url string, body io.Reader, contentType string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, "POST", url, body)
	if err != nil {
		return nil, fmt.Errorf("create request: %w", err)
	}

	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}

	resp, err := c.Do(ctx, req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read response: %w", err)
	}

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("API error (status %d): %s", resp.StatusCode, string(respBody))
	}

	return respBody, nil
}
