package config

import (
	"fmt"
	"os"
	"strings"

	"github.com/nelssec/qualys-mcp/internal/credentials"
)

type Config struct {
	Pod            string
	Username       string
	Password       string
	BearerToken    string
	EnabledModules []string
	BaseURL        string
	GatewayURL     string

	AuditLogPath    string
	RateLimitPerMin int
	ValidateInputs  bool
}

var podURLs = map[string]struct{ API, Gateway string }{
	"US1": {"https://qualysapi.qualys.com", "https://gateway.qg1.apps.qualys.com"},
	"US2": {"https://qualysapi.qg2.apps.qualys.com", "https://gateway.qg2.apps.qualys.com"},
	"US3": {"https://qualysapi.qg3.apps.qualys.com", "https://gateway.qg3.apps.qualys.com"},
	"US4": {"https://qualysapi.qg4.apps.qualys.com", "https://gateway.qg4.apps.qualys.com"},
	"EU1": {"https://qualysapi.qualys.eu", "https://gateway.qg1.apps.qualys.eu"},
	"EU2": {"https://qualysapi.qg2.apps.qualys.eu", "https://gateway.qg2.apps.qualys.eu"},
	"EU3": {"https://qualysapi.qg3.apps.qualys.eu", "https://gateway.qg3.apps.qualys.eu"},
	"CA1": {"https://qualysapi.qg1.apps.qualys.ca", "https://gateway.qg1.apps.qualys.ca"},
	"IN1": {"https://qualysapi.qg1.apps.qualys.in", "https://gateway.qg1.apps.qualys.in"},
	"AE1": {"https://qualysapi.qg1.apps.qualys.ae", "https://gateway.qg1.apps.qualys.ae"},
	"UK1": {"https://qualysapi.qg1.apps.qualys.co.uk", "https://gateway.qg1.apps.qualys.co.uk"},
	"AU1": {"https://qualysapi.qg1.apps.qualys.com.au", "https://gateway.qg1.apps.qualys.com.au"},
}

func Load() (*Config, error) {
	customAPIURL := os.Getenv("QUALYS_API_URL")
	customGatewayURL := os.Getenv("QUALYS_GATEWAY_URL")
	platform := strings.TrimSpace(os.Getenv("QUALYS_PLATFORM"))

	var baseURL, gatewayURL string
	pod := strings.ToUpper(os.Getenv("QUALYS_POD"))

	if platform != "" {
		platform = strings.TrimPrefix(platform, "https://")
		platform = strings.TrimPrefix(platform, "http://")
		platform = strings.TrimSuffix(platform, "/")

		if strings.HasPrefix(platform, "qualysguard.") {
			base := strings.TrimPrefix(platform, "qualysguard.")
			baseURL = "https://qualysapi." + base
			gatewayURL = "https://gateway." + base
		} else {
			baseURL = "https://qualysapi." + platform
			gatewayURL = "https://gateway." + platform
		}
		if pod == "" {
			pod = "CUSTOM"
		}
	} else if customAPIURL != "" && customGatewayURL != "" {
		baseURL = strings.TrimSuffix(customAPIURL, "/")
		gatewayURL = strings.TrimSuffix(customGatewayURL, "/")
		if pod == "" {
			pod = "CUSTOM"
		}
	} else if pod == "" {
		return nil, fmt.Errorf(`QUALYS_POD environment variable is required.

Available PODs:
  US1  - US Platform 1 (qualysapi.qualys.com)
  US2  - US Platform 2 (qualysapi.qg2.apps.qualys.com)
  US3  - US Platform 3 (qualysapi.qg3.apps.qualys.com)
  US4  - US Platform 4 (qualysapi.qg4.apps.qualys.com)
  EU1  - EU Platform 1 (qualysapi.qualys.eu)
  EU2  - EU Platform 2 (qualysapi.qg2.apps.qualys.eu)
  EU3  - EU Platform 3 (qualysapi.qg3.apps.qualys.it)
  CA1  - Canada (qualysapi.qg1.apps.qualys.ca)
  IN1  - India (qualysapi.qg1.apps.qualys.in)
  AE1  - UAE (qualysapi.qg1.apps.qualys.ae)
  UK1  - UK (qualysapi.qg1.apps.qualys.co.uk)
  AU1  - Australia (qualysapi.qg1.apps.qualys.com.au)

For engineering/dev environments, use QUALYS_PLATFORM:
  export QUALYS_PLATFORM=qualysguard.p03.eng.sjc.qualys.com

Or specify custom URLs directly:
  QUALYS_API_URL      - Custom API base URL
  QUALYS_GATEWAY_URL  - Custom Gateway URL

Find your POD at: https://www.qualys.com/platform-identification/

Set with: export QUALYS_POD=<pod>`)
	} else {
		urls, ok := podURLs[pod]
		if !ok {
			return nil, fmt.Errorf("unknown POD: %s. See https://www.qualys.com/platform-identification/", pod)
		}
		baseURL = urls.API
		gatewayURL = urls.Gateway
	}

	modules := os.Getenv("QUALYS_MODULES")
	if modules == "" {
		modules = "vmdr,container,gav,knowledgebase,totalcloud,patch,edr,fim,was,compliance,certview,car,activitylog,workflows"
	}

	rateLimit := 100
	if rl := os.Getenv("QUALYS_RATE_LIMIT"); rl != "" {
		if _, err := fmt.Sscanf(rl, "%d", &rateLimit); err != nil {
			rateLimit = 100
		}
	}

	credMgr := credentials.NewDefaultManager()

	username := os.Getenv("QUALYS_USERNAME")
	password := os.Getenv("QUALYS_PASSWORD")

	if username == "" {
		if u, err := credMgr.GetUsername(); err == nil && u != "" {
			username = u
		}
	}
	if password == "" {
		if p, err := credMgr.GetPassword(); err == nil && p != "" {
			password = p
		}
	}

	bearerToken := os.Getenv("QUALYS_BEARER_TOKEN")

	return &Config{
		Pod:             pod,
		Username:        username,
		Password:        password,
		BearerToken:     bearerToken,
		EnabledModules:  strings.Split(modules, ","),
		BaseURL:         baseURL,
		GatewayURL:      gatewayURL,
		AuditLogPath:    os.Getenv("QUALYS_AUDIT_LOG"),
		RateLimitPerMin: rateLimit,
		ValidateInputs:  os.Getenv("QUALYS_VALIDATE_INPUTS") != "false",
	}, nil
}

func (c *Config) IsModuleEnabled(module string) bool {
	for _, m := range c.EnabledModules {
		if strings.TrimSpace(strings.ToLower(m)) == strings.ToLower(module) {
			return true
		}
	}
	return false
}
