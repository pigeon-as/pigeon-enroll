package verify

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/hashicorp/hcl/v2"
	"github.com/hashicorp/hcl/v2/gohcl"
	"github.com/ovh/go-ovh/ovh"
)

// OVHConfig holds OVH API credentials.
type OVHConfig struct {
	Endpoint          string `hcl:"endpoint,optional"`
	ApplicationKey    string `hcl:"application_key,optional"`
	ApplicationSecret string `hcl:"application_secret,optional"`
	ConsumerKey       string `hcl:"consumer_key,optional"`
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

func newOVH(logger *slog.Logger, body hcl.Body) (*OVH, error) {
	var oc OVHConfig
	if body == nil {
		return nil, fmt.Errorf("ovh verifier: config required")
	}
	if diags := gohcl.DecodeBody(body, nil, &oc); diags.HasErrors() {
		return nil, fmt.Errorf("ovh verifier config: %s", diags.Error())
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
