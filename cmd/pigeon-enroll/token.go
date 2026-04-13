package main

import (
	"fmt"
	"os"
	"time"

	"github.com/pigeon-as/pigeon-enroll/internal/token"
)

func cmdGenerateToken(args []string) int {
	flags := newFlagSet("generate-token")
	configPath := flags.String("config", defaultConfigPath, "Path to HCL config file")
	keyPathFlag := flags.String("key-path", "", "Override enrollment key path from config")
	scope := flags.String("scope", "", "Scope for token generation")
	flags.Parse(args)

	_, cfg, _, hmacKey, err := loadConfig(*configPath, "info", *keyPathFlag)
	if err != nil {
		fmt.Fprintf(os.Stderr, "%v\n", err)
		return 1
	}
	fmt.Print(token.Generate(hmacKey, time.Now(), cfg.TokenWindow, *scope))
	return 0
}
