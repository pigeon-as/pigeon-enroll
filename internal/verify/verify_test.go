package verify

import (
	"context"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/hashicorp/hcl/v2"
	hcljson "github.com/hashicorp/hcl/v2/json"
)

func jsonToBody(t *testing.T, data []byte) hcl.Body {
	t.Helper()
	f, diags := hcljson.Parse(data, "test.json")
	if diags.HasErrors() {
		t.Fatalf("parse test body: %s", diags.Error())
	}
	return f.Body
}

func fakeRequest(remoteAddr string) *http.Request {
	r := httptest.NewRequest("POST", "/claim", nil)
	r.RemoteAddr = remoteAddr
	return r
}

func TestCIDRDefaultAllowAll(t *testing.T) {
	v, err := newCIDR(nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, addr := range []string{"10.0.0.1:1234", "192.168.1.1:1234", "1.2.3.4:1234", "[::1]:1234", "[fd10::1]:1234"} {
		if err := v.Verify(context.Background(), fakeRequest(addr)); err != nil {
			t.Errorf("expected %s allowed by default, got: %v", addr, err)
		}
	}
}

func TestCIDRRestricted(t *testing.T) {
	body := jsonToBody(t, []byte(`{"allow": ["10.0.0.0/8"]}`))
	v, err := newCIDR(body)
	if err != nil {
		t.Fatal(err)
	}

	if err := v.Verify(context.Background(), fakeRequest("10.1.2.3:1234")); err != nil {
		t.Errorf("expected 10.1.2.3 allowed: %v", err)
	}
	if err := v.Verify(context.Background(), fakeRequest("192.168.1.1:1234")); err == nil {
		t.Error("expected 192.168.1.1 denied")
	}
}

func TestCIDRInvalidIP(t *testing.T) {
	v, err := newCIDR(nil)
	if err != nil {
		t.Fatal(err)
	}
	r := httptest.NewRequest("POST", "/claim", nil)
	r.RemoteAddr = "not-an-ip"
	if err := v.Verify(context.Background(), r); err == nil {
		t.Error("expected error for invalid IP")
	}
}

func TestCIDRInvalidConfig(t *testing.T) {
	body := jsonToBody(t, []byte(`{"allow": ["not-a-cidr"]}`))
	_, err := newCIDR(body)
	if err == nil {
		t.Error("expected error for invalid CIDR")
	}
}

func TestNewCIDRViaFactory(t *testing.T) {
	logger := slog.Default()
	v, err := New(logger, []Config{
		{Type: "cidr", Body: jsonToBody(t, []byte(`{"allow": ["10.0.0.0/8"]}`))},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := v.Verify(context.Background(), fakeRequest("10.1.2.3:1234")); err != nil {
		t.Errorf("expected allowed: %v", err)
	}
}

func TestOVHMissingConfig(t *testing.T) {
	logger := slog.Default()
	_, err := New(logger, []Config{{Type: "ovh"}})
	if err == nil {
		t.Error("expected error for missing OVH config")
	}
}

func TestOVHIncompleteConfig(t *testing.T) {
	logger := slog.Default()
	_, err := New(logger, []Config{
		{Type: "ovh", Body: jsonToBody(t, []byte(`{"endpoint": "ovh-eu"}`))},
	})
	if err == nil {
		t.Error("expected error for incomplete OVH config")
	}
}
