package server

import (
	"context"
	"fmt"
	"io"

	"github.com/nelssec/qualys-mcp/config"
	"github.com/nelssec/qualys-mcp/internal/auth"
	"github.com/nelssec/qualys-mcp/internal/common"
	"github.com/nelssec/qualys-mcp/internal/modules/car"
	"github.com/nelssec/qualys-mcp/internal/modules/certview"
	"github.com/nelssec/qualys-mcp/internal/modules/compliance"
	"github.com/nelssec/qualys-mcp/internal/modules/container"
	"github.com/nelssec/qualys-mcp/internal/modules/edr"
	"github.com/nelssec/qualys-mcp/internal/modules/fim"
	"github.com/nelssec/qualys-mcp/internal/modules/gav"
	"github.com/nelssec/qualys-mcp/internal/modules/knowledgebase"
	"github.com/nelssec/qualys-mcp/internal/modules/patch"
	"github.com/nelssec/qualys-mcp/internal/modules/totalcloud"
	"github.com/nelssec/qualys-mcp/internal/modules/vmdr"
	"github.com/nelssec/qualys-mcp/internal/modules/was"
	"github.com/nelssec/qualys-mcp/internal/modules/workflows"
	"github.com/mark3labs/mcp-go/server"
)

type Server struct {
	mcp         *server.MCPServer
	config      *config.Config
	http        *common.HTTPClient
	gatewayHTTP *common.HTTPClient
	auth        *auth.TokenManager
}

func LoadConfig() (*config.Config, error) {
	return config.Load()
}

func New(cfg *config.Config) (*Server, error) {
	basicAuthMgr := auth.NewTokenManager(cfg.GatewayURL, cfg.Username, cfg.Password)
	basicClient := common.NewHTTPClient(basicAuthMgr)

	var gatewayClient *common.HTTPClient
	if cfg.BearerToken != "" {
		bearerAuthMgr := auth.NewBearerTokenManager(cfg.BearerToken)
		gatewayClient = common.NewHTTPClient(bearerAuthMgr)
	} else if cfg.Username != "" && cfg.Password != "" {
		gatewayAuthMgr := auth.NewGatewayTokenManager(cfg.GatewayURL, cfg.Username, cfg.Password)
		_ = gatewayAuthMgr.EnsureToken(context.Background())
		gatewayClient = common.NewHTTPClient(gatewayAuthMgr)
	}

	mcpServer := server.NewMCPServer(
		"qualys-mcp",
		"1.0.0",
		server.WithToolCapabilities(true),
	)

	s := &Server{
		mcp:         mcpServer,
		config:      cfg,
		http:        basicClient,
		gatewayHTTP: gatewayClient,
		auth:        basicAuthMgr,
	}

	s.registerModules()

	return s, nil
}

func (s *Server) registerModules() {
	var gavClient *gav.Client
	var vmdrClient *vmdr.Client
	var kbClient *knowledgebase.Client
	var pmClient *patch.Client
	var carClient *car.Client
	var wasClient *was.Client
	var containerClient *container.Client

	if s.config.IsModuleEnabled("vmdr") {
		vmdrClient = vmdr.NewClient(s.http, s.config.BaseURL)
		vmdrModule := vmdr.NewWithClient(vmdrClient)
		vmdrModule.RegisterTools(s.mcp)
	}

	if s.config.IsModuleEnabled("container") && s.gatewayHTTP != nil {
		containerClient = container.NewClient(s.gatewayHTTP, s.config.GatewayURL)
		containerModule := container.NewWithClient(containerClient)
		containerModule.RegisterTools(s.mcp)
	}

	if s.config.IsModuleEnabled("gav") && s.gatewayHTTP != nil {
		gavClient = gav.NewClient(s.gatewayHTTP, s.config.GatewayURL, s.http, s.config.BaseURL)
		gavModule := gav.NewWithClient(gavClient)
		gavModule.RegisterTools(s.mcp)
	}

	if s.config.IsModuleEnabled("knowledgebase") {
		kbClient = knowledgebase.NewClient(s.http, s.config.BaseURL)
		kbModule := knowledgebase.NewWithClient(kbClient)
		kbModule.RegisterTools(s.mcp)
	}

	if s.config.IsModuleEnabled("totalcloud") && s.gatewayHTTP != nil {
		tcModule := totalcloud.New(s.gatewayHTTP, s.config.GatewayURL)
		tcModule.RegisterTools(s.mcp)
	}

	if s.config.IsModuleEnabled("patch") && s.gatewayHTTP != nil {
		pmClient = patch.NewClient(s.gatewayHTTP, s.config.GatewayURL)
		pmModule := patch.NewWithClient(pmClient)
		pmModule.RegisterTools(s.mcp)
	}

	if s.config.IsModuleEnabled("edr") && s.gatewayHTTP != nil {
		edrModule := edr.New(s.gatewayHTTP, s.config.GatewayURL)
		edrModule.RegisterTools(s.mcp)
	}

	if s.config.IsModuleEnabled("fim") && s.gatewayHTTP != nil {
		fimModule := fim.New(s.gatewayHTTP, s.config.GatewayURL)
		fimModule.RegisterTools(s.mcp)
	}

	if s.config.IsModuleEnabled("was") {
		wasClient = was.NewClient(s.http, s.config.BaseURL)
		wasModule := was.NewWithClient(wasClient)
		wasModule.RegisterTools(s.mcp)
	}

	if s.config.IsModuleEnabled("compliance") {
		pcModule := compliance.New(s.http, s.config.BaseURL)
		pcModule.RegisterTools(s.mcp)
	}

	if s.config.IsModuleEnabled("certview") && s.gatewayHTTP != nil {
		cvModule := certview.New(s.gatewayHTTP, s.config.GatewayURL)
		cvModule.RegisterTools(s.mcp)
	}

	if s.config.IsModuleEnabled("car") && s.gatewayHTTP != nil {
		carClient = car.NewClient(s.gatewayHTTP, s.config.GatewayURL)
		carModule := car.NewWithClient(carClient)
		carModule.RegisterTools(s.mcp)
	}

	if s.config.IsModuleEnabled("workflows") {
		workflowsModule := workflows.NewFull(gavClient, vmdrClient, kbClient, pmClient, carClient, wasClient, containerClient)
		workflowsModule.RegisterTools(s.mcp)
	}
}

func (s *Server) Run(stdin io.Reader, stdout io.Writer) error {
	if err := s.auth.EnsureToken(context.Background()); err != nil {
		return fmt.Errorf("authentication failed: %w", err)
	}

	return server.ServeStdio(s.mcp)
}
