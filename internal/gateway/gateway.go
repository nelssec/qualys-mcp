package gateway

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"sync"
	"time"

	"github.com/nelssec/qualys-mcp/internal/domain"
	"github.com/nelssec/qualys-mcp/internal/logging"
	"github.com/nelssec/qualys-mcp/internal/middleware"
	"github.com/nelssec/qualys-mcp/pkg/policy"
)

type Config struct {
	ListenAddr     string
	AuthProvider   AuthProvider
	PolicyEngine   *policy.Engine
	AuditLogger    *middleware.AuditLogger
	Logger         *logging.Logger
	RateLimiter    *middleware.RateLimiter
	Validator      *middleware.Validator
	MCPServerCmd   string
	MCPServerArgs  []string
	HealthPath     string
	MetricsPath    string
}

type Gateway struct {
	config       Config
	logger       *logging.Logger
	mcpServers   map[string]*mcpServerConn
	mcpServersMu sync.RWMutex
	metrics      *Metrics
}

type mcpServerConn struct {
	cmd    *exec.Cmd
	stdin  io.WriteCloser
	stdout io.ReadCloser
	mu     sync.Mutex
}

type JSONRPCRequest struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      interface{}     `json:"id"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params,omitempty"`
}

type JSONRPCResponse struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      interface{}     `json:"id"`
	Result  json.RawMessage `json:"result,omitempty"`
	Error   *JSONRPCError   `json:"error,omitempty"`
}

type JSONRPCError struct {
	Code    int         `json:"code"`
	Message string      `json:"message"`
	Data    interface{} `json:"data,omitempty"`
}

type ToolCallParams struct {
	Name      string                 `json:"name"`
	Arguments map[string]interface{} `json:"arguments,omitempty"`
}

func New(config Config) *Gateway {
	if config.Logger == nil {
		config.Logger = logging.Default()
	}

	return &Gateway{
		config:     config,
		logger:     config.Logger,
		mcpServers: make(map[string]*mcpServerConn),
		metrics:    NewMetrics(),
	}
}

func (g *Gateway) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	switch r.URL.Path {
	case g.config.HealthPath, "/health", "/healthz":
		g.handleHealth(w, r)
		return
	case g.config.MetricsPath, "/metrics":
		g.handleMetrics(w, r)
		return
	case "/ready", "/readyz":
		g.handleReady(w, r)
		return
	}

	g.handleMCPRequest(w, r)
}

func (g *Gateway) handleHealth(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]string{"status": "healthy"})
}

func (g *Gateway) handleReady(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]string{"status": "ready"})
}

func (g *Gateway) handleMetrics(w http.ResponseWriter, r *http.Request) {
	g.metrics.WritePrometheus(w)
}

func (g *Gateway) handleMCPRequest(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	requestID := r.Header.Get("X-Request-ID")
	if requestID == "" {
		requestID = fmt.Sprintf("%d", time.Now().UnixNano())
	}
	ctx = domain.ContextWithRequestID(ctx, requestID)

	user, err := g.authenticate(ctx, r)
	if err != nil {
		g.writeError(w, http.StatusUnauthorized, "AUTH_ERROR", err.Error())
		g.metrics.AuthFailures.Add(1)
		return
	}
	ctx = domain.ContextWithUser(ctx, user)
	g.metrics.AuthSuccesses.Add(1)

	var req JSONRPCRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		g.writeError(w, http.StatusBadRequest, "PARSE_ERROR", "invalid JSON-RPC request")
		return
	}

	if req.Method == "tools/call" {
		g.handleToolCall(ctx, w, user, req)
		return
	}

	g.proxyToMCP(ctx, w, req)
}

func (g *Gateway) authenticate(ctx context.Context, r *http.Request) (*domain.User, error) {
	if g.config.AuthProvider == nil {
		return &domain.User{
			ID:       "anonymous",
			Username: "anonymous",
			Roles:    []string{"anonymous"},
		}, nil
	}

	token := r.Header.Get("Authorization")
	if token == "" {
		token = r.Header.Get("X-API-Key")
	}

	return g.config.AuthProvider.Authenticate(ctx, token)
}

func (g *Gateway) handleToolCall(ctx context.Context, w http.ResponseWriter, user *domain.User, req JSONRPCRequest) {
	var params ToolCallParams
	if err := json.Unmarshal(req.Params, &params); err != nil {
		g.writeError(w, http.StatusBadRequest, "PARSE_ERROR", "invalid tool call params")
		return
	}

	start := time.Now()
	g.metrics.ToolCalls.Add(1)
	g.metrics.ToolCallsByName[params.Name]++

	toolReq := &domain.ToolRequest{
		ID:        fmt.Sprintf("%v", req.ID),
		Tool:      params.Name,
		Arguments: params.Arguments,
		User:      user,
		Timestamp: time.Now(),
	}

	if g.config.PolicyEngine != nil {
		if err := g.config.PolicyEngine.Evaluate(ctx, user, params.Name, params.Arguments); err != nil {
			g.logger.PolicyDenied(ctx, user.ID, params.Name, err.Error())
			g.metrics.PolicyDenials.Add(1)
			g.writeJSONRPCError(w, req.ID, -32600, err.Error())
			return
		}
	}

	if g.config.Validator != nil {
		validator := g.config.Validator.Middleware()
		handler := func(ctx context.Context, req *domain.ToolRequest) (*domain.ToolResponse, error) {
			return nil, nil
		}
		resp, _ := validator(handler)(ctx, toolReq)
		if resp != nil && resp.Error != nil {
			g.writeJSONRPCError(w, req.ID, -32602, resp.Error.Error())
			return
		}
	}

	if g.config.RateLimiter != nil {
		limiter := g.config.RateLimiter.Middleware()
		handler := func(ctx context.Context, req *domain.ToolRequest) (*domain.ToolResponse, error) {
			return nil, nil
		}
		resp, _ := limiter(handler)(ctx, toolReq)
		if resp != nil && resp.Error != nil {
			g.metrics.RateLimited.Add(1)
			g.writeJSONRPCError(w, req.ID, -32000, resp.Error.Error())
			return
		}
	}

	g.proxyToMCP(ctx, w, req)

	duration := time.Since(start)
	g.metrics.ToolDuration.Observe(duration.Seconds())

	if g.config.AuditLogger != nil {
		auditMiddleware := g.config.AuditLogger.Middleware()
		handler := func(ctx context.Context, req *domain.ToolRequest) (*domain.ToolResponse, error) {
			return &domain.ToolResponse{ID: req.ID, Success: true}, nil
		}
		_, _ = auditMiddleware(handler)(ctx, toolReq)
	}
}

func (g *Gateway) proxyToMCP(ctx context.Context, w http.ResponseWriter, req JSONRPCRequest) {
	reqBytes, err := json.Marshal(req)
	if err != nil {
		g.writeError(w, http.StatusInternalServerError, "MARSHAL_ERROR", "failed to marshal request")
		return
	}

	w.Header().Set("Content-Type", "application/json")
	if _, err := w.Write(reqBytes); err != nil {
		g.logger.Error("failed to write response", "error", err)
	}
}

func (g *Gateway) writeError(w http.ResponseWriter, status int, code, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]interface{}{
		"error": map[string]string{
			"code":    code,
			"message": message,
		},
	})
}

func (g *Gateway) writeJSONRPCError(w http.ResponseWriter, id interface{}, code int, message string) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(JSONRPCResponse{
		JSONRPC: "2.0",
		ID:      id,
		Error: &JSONRPCError{
			Code:    code,
			Message: message,
		},
	})
}

func (g *Gateway) Start() error {
	addr := g.config.ListenAddr
	if addr == "" {
		addr = ":8080"
	}

	server := &http.Server{
		Addr:              addr,
		Handler:           g,
		ReadTimeout:       30 * time.Second,
		ReadHeaderTimeout: 10 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       120 * time.Second,
		MaxHeaderBytes:    1 << 20,
	}

	g.logger.Info("starting gateway", "addr", addr)
	return server.ListenAndServe()
}

func (g *Gateway) ServeStdio(mcpCmd string, args ...string) error {
	cmd := exec.Command(mcpCmd, args...)

	mcpStdin, err := cmd.StdinPipe()
	if err != nil {
		return fmt.Errorf("create stdin pipe: %w", err)
	}

	mcpStdout, err := cmd.StdoutPipe()
	if err != nil {
		return fmt.Errorf("create stdout pipe: %w", err)
	}

	cmd.Stderr = os.Stderr

	if err := cmd.Start(); err != nil {
		return fmt.Errorf("start MCP server: %w", err)
	}

	go g.handleStdioInput(mcpStdin, mcpStdout)

	return cmd.Wait()
}

func (g *Gateway) handleStdioInput(mcpStdin io.WriteCloser, mcpStdout io.ReadCloser) {
	scanner := bufio.NewScanner(os.Stdin)
	mcpScanner := bufio.NewScanner(mcpStdout)

	go func() {
		for mcpScanner.Scan() {
			fmt.Fprintln(os.Stdout, mcpScanner.Text())
		}
	}()

	for scanner.Scan() {
		line := scanner.Text()
		ctx := context.Background()

		var req JSONRPCRequest
		if err := json.Unmarshal([]byte(line), &req); err != nil {
			fmt.Fprintln(mcpStdin, line)
			continue
		}

		user := &domain.User{
			ID:       os.Getenv("MCP_USER_ID"),
			Username: os.Getenv("MCP_USERNAME"),
			Roles:    []string{os.Getenv("MCP_USER_ROLE")},
		}
		if user.ID == "" {
			user.ID = "local"
			user.Username = "local"
			user.Roles = []string{"admin"}
		}

		if req.Method == "tools/call" {
			var params ToolCallParams
			if err := json.Unmarshal(req.Params, &params); err == nil {
				if g.config.PolicyEngine != nil {
					if err := g.config.PolicyEngine.Evaluate(ctx, user, params.Name, params.Arguments); err != nil {
						g.logger.PolicyDenied(ctx, user.ID, params.Name, err.Error())
						errResp := JSONRPCResponse{
							JSONRPC: "2.0",
							ID:      req.ID,
							Error: &JSONRPCError{
								Code:    -32600,
								Message: err.Error(),
							},
						}
						respBytes, _ := json.Marshal(errResp)
						fmt.Fprintln(os.Stdout, string(respBytes))
						continue
					}
				}
			}
		}

		fmt.Fprintln(mcpStdin, line)
	}
}
