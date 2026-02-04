package auth

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

type AuthMethod int

const (
	AuthBasic AuthMethod = iota
	AuthBearer
)

type TokenManager struct {
	gatewayURL  string
	username    string
	password    string
	bearerToken string
	tokenExpiry time.Time
	authMethod  AuthMethod

	mu sync.RWMutex
}

func NewTokenManager(gatewayURL, username, password string) *TokenManager {
	return &TokenManager{
		gatewayURL: gatewayURL,
		username:   username,
		password:   password,
		authMethod: AuthBasic,
	}
}

func NewBearerTokenManager(token string) *TokenManager {
	return &TokenManager{
		bearerToken: token,
		authMethod:  AuthBearer,
	}
}

func NewGatewayTokenManager(gatewayURL, username, password string) *TokenManager {
	return &TokenManager{
		gatewayURL: gatewayURL,
		username:   username,
		password:   password,
		authMethod: AuthBearer,
	}
}

func (tm *TokenManager) GetCredentials() (username, password string) {
	tm.mu.RLock()
	defer tm.mu.RUnlock()
	return tm.username, tm.password
}

func (tm *TokenManager) GetBearerToken() string {
	tm.mu.RLock()
	defer tm.mu.RUnlock()
	return tm.bearerToken
}

func (tm *TokenManager) SetBearerToken(token string) {
	tm.mu.Lock()
	defer tm.mu.Unlock()
	tm.bearerToken = token
	tm.authMethod = AuthBearer
}

func (tm *TokenManager) AuthMethod() AuthMethod {
	tm.mu.RLock()
	defer tm.mu.RUnlock()
	return tm.authMethod
}

func (tm *TokenManager) ApplyAuth(req *http.Request) {
	tm.mu.RLock()
	defer tm.mu.RUnlock()

	switch tm.authMethod {
	case AuthBearer:
		if tm.bearerToken != "" {
			req.Header.Set("Authorization", "Bearer "+tm.bearerToken)
		}
	case AuthBasic:
		fallthrough
	default:
		if tm.username != "" && tm.password != "" {
			req.SetBasicAuth(tm.username, tm.password)
		}
	}
}

func (tm *TokenManager) EnsureToken(ctx context.Context) error {
	if tm.authMethod == AuthBearer && tm.gatewayURL != "" && tm.bearerToken == "" {
		return tm.refreshBearerToken(ctx)
	}
	return nil
}

func (tm *TokenManager) GetToken(ctx context.Context) (string, error) {
	tm.mu.RLock()
	if tm.bearerToken != "" && time.Now().Add(5*time.Minute).Before(tm.tokenExpiry) {
		token := tm.bearerToken
		tm.mu.RUnlock()
		return token, nil
	}
	tm.mu.RUnlock()

	if tm.gatewayURL != "" && tm.username != "" {
		if err := tm.refreshBearerToken(ctx); err != nil {
			return "", err
		}
		tm.mu.RLock()
		defer tm.mu.RUnlock()
		return tm.bearerToken, nil
	}

	return tm.bearerToken, nil
}

func (tm *TokenManager) refreshBearerToken(ctx context.Context) error {
	tm.mu.Lock()
	defer tm.mu.Unlock()

	if tm.bearerToken != "" && time.Now().Add(5*time.Minute).Before(tm.tokenExpiry) {
		return nil
	}

	authURL := tm.gatewayURL + "/auth"

	data := url.Values{}
	data.Set("username", tm.username)
	data.Set("password", tm.password)
	data.Set("token", "true")

	req, err := http.NewRequestWithContext(ctx, "POST", authURL, strings.NewReader(data.Encode()))
	if err != nil {
		return fmt.Errorf("create token request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return fmt.Errorf("token request failed: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("read token response: %w", err)
	}

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
		return fmt.Errorf("token request failed with status %d: %s", resp.StatusCode, string(body))
	}

	token := strings.TrimSpace(string(body))
	if token == "" {
		return fmt.Errorf("empty token received")
	}

	tm.bearerToken = token
	tm.tokenExpiry = time.Now().Add(4 * time.Hour)

	return nil
}

type jwtClaims struct {
	Exp int64 `json:"exp"`
}

func parseJWTExpiry(token string) time.Time {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return time.Now().Add(4 * time.Hour)
	}

	var claims jwtClaims
	if err := json.Unmarshal([]byte(parts[1]), &claims); err != nil {
		return time.Now().Add(4 * time.Hour)
	}

	if claims.Exp > 0 {
		return time.Unix(claims.Exp, 0)
	}
	return time.Now().Add(4 * time.Hour)
}
