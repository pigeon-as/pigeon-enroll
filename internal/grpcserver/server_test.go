package grpcserver

import (
	"crypto/tls"
	"errors"
	"fmt"
	"log/slog"
	"testing"

	"github.com/pigeon-as/pigeon-enroll/internal/config"
	"github.com/pigeon-as/pigeon-enroll/internal/identity"
	"github.com/pigeon-as/pigeon-enroll/internal/policy"
	"github.com/pigeon-as/pigeon-enroll/internal/resource"
	"github.com/shoenig/test/must"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func TestNew_RejectsEmptyIKM(t *testing.T) {
	cfg := &config.Config{}
	eng := &policy.Engine{}
	reg := &identity.Registry{}
	res := &resource.Resolver{}
	cfg.TrustDomain = "example.test"
	_, err := New(cfg, eng, reg, res, nil, nil, Options{})
	must.ErrorContains(t, err, "empty ikm")
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
	cfg.TrustDomain = "example.test"
	s, err := New(cfg, eng, reg, res, nil, ikm, Options{})
	must.NoError(t, err)
	tc := s.TLSConfig()
	must.EqOp(t, uint16(tls.VersionTLS13), tc.MinVersion)
	must.NotNil(t, tc.GetCertificate)
	cert, err := tc.GetCertificate(nil)
	must.NoError(t, err)
	must.NotNil(t, cert)
	must.Positive(t, len(cert.Certificate))
}

func TestMapResolveError(t *testing.T) {
	s := &Server{log: slog.Default()}
	cases := []struct {
		in      error
		want    codes.Code
		wantMsg string
	}{
		{fmt.Errorf("var foo: %w", resource.ErrNotFound), codes.NotFound, "not found"},
		{fmt.Errorf("read on var/foo (policy %q): %w", "worker", resource.ErrPermissionDenied), codes.PermissionDenied, "permission denied"},
		// Arbitrary resolver errors are collapsed to a generic message so we
		// don't leak resource shape to unauthenticated probes.
		{errors.New("pki X references unknown ca Y"), codes.InvalidArgument, "invalid argument"},
		{errors.New("secret not found"), codes.InvalidArgument, "invalid argument"}, // string-contains alone is NOT enough
	}
	for _, c := range cases {
		got := s.mapResolveError(c.in)
		must.EqOp(t, c.want, status.Code(got))
		must.EqOp(t, c.wantMsg, status.Convert(got).Message())
	}
}
