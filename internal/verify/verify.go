// Package verify provides request verification for enrollment claims.
package verify

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net"
	"net/http"
)

// Verifier checks whether a claim request should be allowed.
type Verifier interface {
	Verify(ctx context.Context, r *http.Request) error
}

// Config holds verifier configuration from the enrollment config file.
type Config struct {
	Type   string          `json:"type"`
	Fatal  *bool           `json:"fatal"`
	Config json.RawMessage `json:"config"`
}

// New creates a Verifier from config. Returns Noop if cfgs is empty.
// Multiple configs produce a Chain that runs each verifier in order.
func New(logger *slog.Logger, cfgs []Config) (Verifier, error) {
	if len(cfgs) == 0 {
		return Noop{}, nil
	}
	var entries []chainEntry
	for _, cfg := range cfgs {
		var v Verifier
		var err error
		switch cfg.Type {
		case "", "noop":
			continue
		case "cidr":
			v, err = newCIDR(cfg.Config)
		case "ovh":
			v, err = newOVH(logger, cfg.Config)
		default:
			return nil, fmt.Errorf("unknown verifier type: %q", cfg.Type)
		}
		if err != nil {
			return nil, err
		}
		entries = append(entries, chainEntry{verifier: v, fatal: isFatal(cfg)})
	}
	if len(entries) == 0 {
		return Noop{}, nil
	}
	return &Chain{entries: entries, logger: logger}, nil
}

type chainEntry struct {
	verifier Verifier
	fatal    bool
}

// Chain runs multiple verifiers in order. Fatal verifiers short-circuit on failure.
// Non-fatal verifiers log a warning and continue.
type Chain struct {
	entries []chainEntry
	logger  *slog.Logger
}

func (c *Chain) Verify(ctx context.Context, r *http.Request) error {
	for _, e := range c.entries {
		if err := e.verifier.Verify(ctx, r); err != nil {
			if e.fatal {
				return err
			}
			c.logger.Warn("verification failed (non-fatal)", "err", err)
		}
	}
	return nil
}

// isFatal returns the fatal flag, defaulting to true.
func isFatal(cfg Config) bool {
	if cfg.Fatal != nil {
		return *cfg.Fatal
	}
	return true
}

// Noop always allows claims.
type Noop struct{}

func (Noop) Verify(context.Context, *http.Request) error { return nil }

// ClientIP extracts the client IP from a request, stripping the port.
func ClientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}
