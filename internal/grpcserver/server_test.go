package grpcserver

import (
	"crypto/tls"
	"errors"
	"strings"
	"testing"

	"github.com/pigeon-as/pigeon-enroll/internal/config"
	"github.com/pigeon-as/pigeon-enroll/internal/identity"
	"github.com/pigeon-as/pigeon-enroll/internal/policy"
	"github.com/pigeon-as/pigeon-enroll/internal/resource"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func TestNew_RejectsEmptyIKM(t *testing.T) {
	cfg := &config.Config{}
	eng := &policy.Engine{}
	reg := &identity.Registry{}
	res := &resource.Resolver{}
	_, err := New(cfg, eng, reg, res, nil, nil, Options{Hosts: []string{"localhost"}})
	if err == nil {
		t.Fatal("expected error for empty ikm")
	}
	if !strings.Contains(err.Error(), "empty ikm") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestNew_BuildsServerCAAndTLS(t *testing.T) {
	cfg := &config.Config{}
	eng := &policy.Engine{}
	reg := &identity.Registry{}
	res := &resource.Resolver{}
	ikm := make([]byte, 32)
	for i := range ikm {
		ikm[i] = byte(i)
	}
	s, err := New(cfg, eng, reg, res, ikm, nil, Options{Hosts: []string{"localhost"}})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	tc := s.TLSConfig()
	if tc.MinVersion != tls.VersionTLS13 {
		t.Fatalf("expected TLS 1.3 min, got %d", tc.MinVersion)
	}
	if tc.GetCertificate == nil {
		t.Fatal("expected GetCertificate callback")
	}
	cert, err := tc.GetCertificate(nil)
	if err != nil {
		t.Fatalf("GetCertificate: %v", err)
	}
	if cert == nil || len(cert.Certificate) == 0 {
		t.Fatal("expected non-empty cert")
	}
}

func TestMapResolveError(t *testing.T) {
	cases := []struct {
		in   error
		want codes.Code
	}{
		{errors.New("permission denied: policy foo"), codes.PermissionDenied},
		{errors.New("secret not found"), codes.NotFound},
		{errors.New("bad path"), codes.InvalidArgument},
	}
	for _, c := range cases {
		got := status.Code(mapResolveError(c.in))
		if got != c.want {
			t.Errorf("mapResolveError(%q) = %s, want %s", c.in, got, c.want)
		}
	}
}
