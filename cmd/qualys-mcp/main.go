package main

import (
	"log"
	"os"

	"github.com/nelssec/qualys-mcp/internal/server"
)

func main() {
	cfg, err := server.LoadConfig()
	if err != nil {
		log.Fatalf("Failed to load config: %v", err)
	}

	srv, err := server.New(cfg)
	if err != nil {
		log.Fatalf("Failed to create server: %v", err)
	}

	if err := srv.Run(os.Stdin, os.Stdout); err != nil {
		log.Fatalf("Server error: %v", err)
	}
}
