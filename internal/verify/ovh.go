package verify

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/ovh/go-ovh/ovh"
)

// OVHConfig holds OVH API credentials.
type OVHConfig struct {
	Endpoint          string `json:"endpoint"` // e.g. "ovh-eu"
	ApplicationKey    string `json:"application_key"`
	ApplicationSecret string `json:"application_secret"`
	ConsumerKey       string `json:"consumer_key"`
}

const ipCacheTTL = 5 * time.Minute

// OVH checks whether the client IP belongs to any IP block owned by the OVH account.
// IP blocks are cached for 5 minutes to avoid per-claim API calls.
type OVH struct {
	client *ovh.Client
	logger *slog.Logger

	mu     sync.Mutex
	blocks []*net.IPNet
	expiry time.Time
}

func newOVH(logger *slog.Logger, raw json.RawMessage) (*OVH, error) {
	var oc OVHConfig
	if len(raw) == 0 {
		return nil, fmt.Errorf("ovh verifier: config required")
	}
	if err := json.Unmarshal(raw, &oc); err != nil {
		return nil, fmt.Errorf("ovh verifier config: %w", err)
	}
	if oc.Endpoint == "" || oc.ApplicationKey == "" || oc.ApplicationSecret == "" || oc.ConsumerKey == "" {
		return nil, fmt.Errorf("ovh verifier: endpoint, application_key, application_secret, consumer_key are required")
	}
	client, err := ovh.NewClient(oc.Endpoint, oc.ApplicationKey, oc.ApplicationSecret, oc.ConsumerKey)
	if err != nil {
		return nil, fmt.Errorf("ovh verifier: %w", err)
	}
	return &OVH{client: client, logger: logger}, nil
}

// Verify checks whether the client IP falls within any IP block owned
// by the OVH account. IP blocks are cached for 5 minutes.
func (o *OVH) Verify(ctx context.Context, r *http.Request) error {
	ip := ClientIP(r)
	parsed := net.ParseIP(ip)
	if parsed == nil {
		return fmt.Errorf("invalid IP: %q", ip)
	}

	blocks, err := o.ipBlocks(ctx)
	if err != nil {
		return err
	}

	for _, n := range blocks {
		if n.Contains(parsed) {
			return nil
		}
	}

	return fmt.Errorf("IP %s not in any OVH IP block", ip)
}

// ipBlocks returns cached IP blocks, refreshing from the OVH API if expired.
func (o *OVH) ipBlocks(ctx context.Context) ([]*net.IPNet, error) {
	o.mu.Lock()
	defer o.mu.Unlock()

	if time.Now().Before(o.expiry) {
		return o.blocks, nil
	}

	var raw []string
	if err := o.client.GetWithContext(ctx, "/ip", &raw); err != nil {
		return nil, fmt.Errorf("ovh verifier: GET /ip: %w", err)
	}

	blocks := make([]*net.IPNet, 0, len(raw))
	for _, cidr := range raw {
		_, n, err := net.ParseCIDR(cidr)
		if err != nil {
			o.logger.Warn("skipping unparseable OVH IP block", "block", cidr, "err", err)
			continue
		}
		blocks = append(blocks, n)
	}

	o.blocks = blocks
	o.expiry = time.Now().Add(ipCacheTTL)
	return blocks, nil
}
