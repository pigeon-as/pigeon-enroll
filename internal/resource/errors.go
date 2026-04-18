package resource

import "errors"

// ErrPermissionDenied is returned (wrapped) when a caller's policy does not
// grant the requested capability on the requested path. The gRPC layer maps
// this to codes.PermissionDenied with a generic message so that clients
// cannot enumerate config shape by probing.
var ErrPermissionDenied = errors.New("permission denied")

// ErrNotFound is returned (wrapped) when a named resource (var, secret, ca,
// jwt_key, template, pki, jwt, identity) does not exist. Mapped to
// codes.NotFound with a generic message for the same reason as above.
var ErrNotFound = errors.New("not found")
