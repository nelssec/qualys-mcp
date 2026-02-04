package gateway

import (
	"context"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/nelssec/qualys-mcp/internal/domain"
)

type AuthProvider interface {
	Authenticate(ctx context.Context, token string) (*domain.User, error)
}

type JWTClaims struct {
	Subject   string                 `json:"sub"`
	Email     string                 `json:"email"`
	Name      string                 `json:"name"`
	Roles     []string               `json:"roles"`
	Groups    []string               `json:"groups"`
	ExpiresAt int64                  `json:"exp"`
	IssuedAt  int64                  `json:"iat"`
	Issuer    string                 `json:"iss"`
	Audience  interface{}            `json:"aud"`
	Extra     map[string]interface{} `json:"-"`
}

type JWTAuthConfig struct {
	Issuer         string
	Audience       string
	JWKSUrl        string
	RolesClaimKey  string
	GroupsClaimKey string
}

type JWTAuth struct {
	config     JWTAuthConfig
	jwksCache  map[string]*rsa.PublicKey
	jwksMu     sync.RWMutex
	lastFetch  time.Time
	httpClient *http.Client
}

func NewJWTAuth(config JWTAuthConfig) *JWTAuth {
	return &JWTAuth{
		config:     config,
		jwksCache:  make(map[string]*rsa.PublicKey),
		httpClient: &http.Client{Timeout: 10 * time.Second},
	}
}

func (j *JWTAuth) Authenticate(ctx context.Context, token string) (*domain.User, error) {
	token = strings.TrimPrefix(token, "Bearer ")
	token = strings.TrimSpace(token)

	if token == "" {
		return nil, domain.NewAuthError("missing token")
	}

	claims, err := j.parseAndValidateToken(token)
	if err != nil {
		return nil, domain.NewAuthError(err.Error())
	}

	user := &domain.User{
		ID:       claims.Subject,
		Username: claims.Name,
		Email:    claims.Email,
		Roles:    claims.Roles,
		Claims:   claims.Extra,
	}

	if len(user.Roles) == 0 && len(claims.Groups) > 0 {
		user.Roles = claims.Groups
	}

	return user, nil
}

func (j *JWTAuth) parseAndValidateToken(token string) (*JWTClaims, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil, errors.New("invalid token format")
	}

	payloadBytes, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, fmt.Errorf("decode payload: %w", err)
	}

	var claims JWTClaims
	if err := json.Unmarshal(payloadBytes, &claims); err != nil {
		return nil, fmt.Errorf("parse claims: %w", err)
	}

	var extra map[string]interface{}
	if err := json.Unmarshal(payloadBytes, &extra); err == nil {
		delete(extra, "sub")
		delete(extra, "email")
		delete(extra, "name")
		delete(extra, "roles")
		delete(extra, "groups")
		delete(extra, "exp")
		delete(extra, "iat")
		delete(extra, "iss")
		delete(extra, "aud")
		claims.Extra = extra
	}

	if j.config.RolesClaimKey != "" && j.config.RolesClaimKey != "roles" {
		if roles, ok := extra[j.config.RolesClaimKey].([]interface{}); ok {
			for _, r := range roles {
				if s, ok := r.(string); ok {
					claims.Roles = append(claims.Roles, s)
				}
			}
		}
	}

	now := time.Now().Unix()
	if claims.ExpiresAt > 0 && claims.ExpiresAt < now {
		return nil, errors.New("token expired")
	}

	if j.config.Issuer != "" && claims.Issuer != j.config.Issuer {
		return nil, fmt.Errorf("invalid issuer: expected %s, got %s", j.config.Issuer, claims.Issuer)
	}

	if j.config.Audience != "" {
		if !j.validateAudience(claims.Audience, j.config.Audience) {
			return nil, errors.New("invalid audience")
		}
	}

	return &claims, nil
}

func (j *JWTAuth) validateAudience(aud interface{}, expected string) bool {
	switch a := aud.(type) {
	case string:
		return a == expected
	case []interface{}:
		for _, v := range a {
			if s, ok := v.(string); ok && s == expected {
				return true
			}
		}
	}
	return false
}

func (j *JWTAuth) fetchJWKS(ctx context.Context) error {
	if j.config.JWKSUrl == "" {
		return nil
	}

	j.jwksMu.Lock()
	defer j.jwksMu.Unlock()

	if time.Since(j.lastFetch) < 5*time.Minute && len(j.jwksCache) > 0 {
		return nil
	}

	req, err := http.NewRequestWithContext(ctx, "GET", j.config.JWKSUrl, nil)
	if err != nil {
		return err
	}

	resp, err := j.httpClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	var jwks struct {
		Keys []struct {
			Kid string `json:"kid"`
			Kty string `json:"kty"`
			N   string `json:"n"`
			E   string `json:"e"`
		} `json:"keys"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&jwks); err != nil {
		return err
	}

	for _, key := range jwks.Keys {
		if key.Kty != "RSA" {
			continue
		}

		nBytes, err := base64.RawURLEncoding.DecodeString(key.N)
		if err != nil {
			continue
		}

		eBytes, err := base64.RawURLEncoding.DecodeString(key.E)
		if err != nil {
			continue
		}

		n := new(big.Int).SetBytes(nBytes)
		e := int(new(big.Int).SetBytes(eBytes).Int64())

		j.jwksCache[key.Kid] = &rsa.PublicKey{N: n, E: e}
	}

	j.lastFetch = time.Now()
	return nil
}

type APIKeyAuth struct {
	keys map[string]*domain.User
	mu   sync.RWMutex
}

func NewAPIKeyAuth() *APIKeyAuth {
	return &APIKeyAuth{
		keys: make(map[string]*domain.User),
	}
}

func (a *APIKeyAuth) AddKey(key string, user *domain.User) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.keys[key] = user
}

func (a *APIKeyAuth) Authenticate(ctx context.Context, token string) (*domain.User, error) {
	token = strings.TrimPrefix(token, "ApiKey ")
	token = strings.TrimSpace(token)

	a.mu.RLock()
	user, ok := a.keys[token]
	a.mu.RUnlock()

	if !ok {
		return nil, domain.NewAuthError("invalid API key")
	}

	return user, nil
}

type ChainAuth struct {
	providers []AuthProvider
}

func NewChainAuth(providers ...AuthProvider) *ChainAuth {
	return &ChainAuth{providers: providers}
}

func (c *ChainAuth) Authenticate(ctx context.Context, token string) (*domain.User, error) {
	var lastErr error
	for _, provider := range c.providers {
		user, err := provider.Authenticate(ctx, token)
		if err == nil {
			return user, nil
		}
		lastErr = err
	}
	if lastErr != nil {
		return nil, lastErr
	}
	return nil, domain.NewAuthError("no auth provider succeeded")
}

type NoAuth struct {
	defaultUser *domain.User
}

func NewNoAuth(defaultUser *domain.User) *NoAuth {
	return &NoAuth{defaultUser: defaultUser}
}

func (n *NoAuth) Authenticate(ctx context.Context, token string) (*domain.User, error) {
	if n.defaultUser != nil {
		return n.defaultUser, nil
	}
	return &domain.User{
		ID:       "anonymous",
		Username: "anonymous",
		Roles:    []string{"anonymous"},
	}, nil
}
