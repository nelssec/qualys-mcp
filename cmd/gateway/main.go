package main

import (
	"flag"
	"log"
	"os"
	"strconv"
	"time"

	"github.com/nelssec/qualys-mcp/internal/domain"
	"github.com/nelssec/qualys-mcp/internal/gateway"
	"github.com/nelssec/qualys-mcp/internal/logging"
	"github.com/nelssec/qualys-mcp/internal/middleware"
	"github.com/nelssec/qualys-mcp/pkg/policy"
)

func main() {
	var (
		mode        = flag.String("mode", "stdio", "Mode: stdio or http")
		addr        = flag.String("addr", ":8080", "HTTP listen address")
		policyFile  = flag.String("policy", "", "Policy configuration file")
		auditLog    = flag.String("audit-log", "", "Audit log file path")
		mcpServer   = flag.String("mcp-server", "./qualys-mcp", "Path to MCP server binary")
		logLevel    = flag.String("log-level", "info", "Log level: debug, info, warn, error")
		logFormat   = flag.String("log-format", "json", "Log format: json or text")
		jwtIssuer   = flag.String("jwt-issuer", "", "JWT issuer for validation")
		jwtAudience = flag.String("jwt-audience", "", "JWT audience for validation")
		jwksURL     = flag.String("jwks-url", "", "JWKS URL for JWT validation")
		rateLimit   = flag.Int("rate-limit", 100, "Rate limit per minute per user")
		validate    = flag.Bool("validate", true, "Enable input validation")
	)
	flag.Parse()

	if envMode := os.Getenv("MCP_GATEWAY_MODE"); envMode != "" {
		*mode = envMode
	}
	if envAddr := os.Getenv("MCP_GATEWAY_ADDR"); envAddr != "" {
		*addr = envAddr
	}
	if envPolicy := os.Getenv("MCP_GATEWAY_POLICIES"); envPolicy != "" {
		*policyFile = envPolicy
	}
	if envAudit := os.Getenv("MCP_GATEWAY_AUDIT_LOG"); envAudit != "" {
		*auditLog = envAudit
	}
	if envMCP := os.Getenv("MCP_SERVER_PATH"); envMCP != "" {
		*mcpServer = envMCP
	}
	if envIssuer := os.Getenv("MCP_JWT_ISSUER"); envIssuer != "" {
		*jwtIssuer = envIssuer
	}
	if envAud := os.Getenv("MCP_JWT_AUDIENCE"); envAud != "" {
		*jwtAudience = envAud
	}
	if envJWKS := os.Getenv("MCP_JWKS_URL"); envJWKS != "" {
		*jwksURL = envJWKS
	}
	if envRate := os.Getenv("MCP_RATE_LIMIT"); envRate != "" {
		if r, err := strconv.Atoi(envRate); err == nil {
			*rateLimit = r
		}
	}

	logCfg := logging.DefaultConfig()
	logCfg.Format = *logFormat
	switch *logLevel {
	case "debug":
		logCfg.Level = -4
	case "warn":
		logCfg.Level = 4
	case "error":
		logCfg.Level = 8
	}
	logger := logging.New(logCfg)

	var authProvider gateway.AuthProvider
	if *jwtIssuer != "" || *jwksURL != "" {
		authProvider = gateway.NewJWTAuth(gateway.JWTAuthConfig{
			Issuer:   *jwtIssuer,
			Audience: *jwtAudience,
			JWKSUrl:  *jwksURL,
		})
		logger.Info("JWT authentication enabled", "issuer", *jwtIssuer)
	} else {
		authProvider = gateway.NewNoAuth(&domain.User{
			ID:       "default",
			Username: "default",
			Roles:    []string{"user"},
		})
		logger.Info("No authentication configured, using default user")
	}

	var policyEngine *policy.Engine
	if *policyFile != "" {
		policyEngine = policy.NewEngine()
		if err := policyEngine.LoadFromFile(*policyFile); err != nil {
			log.Fatalf("Failed to load policy file: %v", err)
		}
		logger.Info("Policy engine loaded", "file", *policyFile)
	}

	var auditLogger *middleware.AuditLogger
	if *auditLog != "" {
		var err error
		auditLogger, err = middleware.NewAuditLogger(*auditLog)
		if err != nil {
			log.Fatalf("Failed to create audit logger: %v", err)
		}
		logger.Info("Audit logging enabled", "file", *auditLog)
	}

	var rateLimiter *middleware.RateLimiter
	if *rateLimit > 0 {
		rateLimiter = middleware.NewRateLimiter(*rateLimit, time.Minute, logger)
		logger.Info("Rate limiting enabled", "limit", *rateLimit, "window", "1m")
	}

	var validator *middleware.Validator
	if *validate {
		validator = middleware.NewValidator(true)
		logger.Info("Input validation enabled")
	}

	gw := gateway.New(gateway.Config{
		ListenAddr:   *addr,
		AuthProvider: authProvider,
		PolicyEngine: policyEngine,
		AuditLogger:  auditLogger,
		Logger:       logger,
		RateLimiter:  rateLimiter,
		Validator:    validator,
		MCPServerCmd: *mcpServer,
		HealthPath:   "/health",
		MetricsPath:  "/metrics",
	})

	switch *mode {
	case "http":
		logger.Info("Starting MCP Gateway in HTTP mode", "addr", *addr)
		if err := gw.Start(); err != nil {
			log.Fatalf("Gateway error: %v", err)
		}
	case "stdio":
		logger.Info("Starting MCP Gateway in stdio mode", "mcp_server", *mcpServer)
		if err := gw.ServeStdio(*mcpServer); err != nil {
			log.Fatalf("Gateway error: %v", err)
		}
	default:
		log.Fatalf("Unknown mode: %s", *mode)
	}
}
