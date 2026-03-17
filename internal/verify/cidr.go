package verify

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
)

// CIDRConfig holds the allowlist of CIDR ranges.
type CIDRConfig struct {
	Allow []string `json:"allow"` // e.g. ["10.0.0.0/8", "0.0.0.0/0"]
}

// CIDR checks whether the client IP falls within any of the configured ranges.
type CIDR struct {
	nets []*net.IPNet
}

func newCIDR(raw json.RawMessage) (*CIDR, error) {
	var cc CIDRConfig
	if len(raw) > 0 {
		if err := json.Unmarshal(raw, &cc); err != nil {
			return nil, fmt.Errorf("cidr verifier config: %w", err)
		}
	}
	if len(cc.Allow) == 0 {
		cc.Allow = []string{"0.0.0.0/0", "::/0"}
	}
	nets := make([]*net.IPNet, 0, len(cc.Allow))
	for _, cidr := range cc.Allow {
		_, n, err := net.ParseCIDR(cidr)
		if err != nil {
			return nil, fmt.Errorf("cidr verifier: invalid CIDR %q: %w", cidr, err)
		}
		nets = append(nets, n)
	}
	return &CIDR{nets: nets}, nil
}

func (c *CIDR) Verify(_ context.Context, r *http.Request) error {
	ip := ClientIP(r)
	parsed := net.ParseIP(ip)
	if parsed == nil {
		return fmt.Errorf("invalid IP: %q", ip)
	}
	for _, n := range c.nets {
		if n.Contains(parsed) {
			return nil
		}
	}
	return fmt.Errorf("IP %s not in allowed CIDRs", ip)
}
