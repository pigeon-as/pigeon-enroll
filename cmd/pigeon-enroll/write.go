package main

import (
"context"
"flag"
"fmt"
"os"
"strings"
"time"

enrollv1 "github.com/pigeon-as/pigeon-enroll/proto/enroll/v1"
)

// cmdWrite implements `pigeon-enroll write <path> [key=value ...]`.
//
// Write produces a fresh artifact at a mutating path and returns one
// scalar. Values prefixed with '@' are read from a file.
//
// Paths:
//   pki/<role>   csr=@file.der (DER PKCS#10, required)  -> cert PEM
//   jwt/<name>   no inputs                              -> signed token
func cmdWrite(args []string) int {
fs := flag.NewFlagSet("write", flag.ContinueOnError)
fs.Usage = func() {
fmt.Fprintln(os.Stderr, `Usage: pigeon-enroll write [flags] <path> [key=value ...]

Write to a mutating resource. Paths:
  pki/<role>   csr=@file.der    sign the CSR, return cert PEM
  jwt/<name>                    sign a JWT with the named key

Flags:`)
fs.PrintDefaults()
}
cf := registerClientFlags(fs)
outPath := fs.String("o", "", "output file (default stdout)")
timeout := fs.Duration("timeout", 30*time.Second, "write timeout")
if err := fs.Parse(args); err != nil {
return 2
}
rest := fs.Args()
if len(rest) < 1 {
fs.Usage()
return 2
}
data := map[string][]byte{}
for _, kv := range rest[1:] {
eq := strings.IndexByte(kv, '=')
if eq <= 0 {
fmt.Fprintf(os.Stderr, "invalid input %q; expected key=value\n", kv)
return 2
}
key := kv[:eq]
val, err := readValueOrFile(kv[eq+1:])
if err != nil {
fmt.Fprintf(os.Stderr, "read %s: %v\n", key, err)
return 1
}
data[key] = val
}
return dispatchScalar(cf, *outPath, *timeout, rest[0], data, /*write=*/ true)
}

// dispatchScalar performs a Read or Write and emits the single scalar
// response to stdout or outPath.
func dispatchScalar(cf *clientFlags, outPath string, timeout time.Duration, path string, data map[string][]byte, write bool) int {
conn, err := dialServer(cf.addr, cf.ca, identityBundlePath(cf.identityDir))
if err != nil {
fmt.Fprintf(os.Stderr, "dial: %v\n", err)
return 1
}
defer conn.Close()

ctx, cancel := context.WithTimeout(context.Background(), timeout)
defer cancel()

client := enrollv1.NewEnrollClient(conn)
req := &enrollv1.Request{Path: path, Data: data}
var resp *enrollv1.Response
if write {
resp, err = client.Write(ctx, req)
} else {
resp, err = client.Read(ctx, req)
}
if err != nil {
verb := "read"
if write {
verb = "write"
}
fmt.Fprintf(os.Stderr, "%s: %v\n", verb, err)
return 1
}

if outPath == "" {
if _, err := os.Stdout.Write(resp.Content); err != nil {
fmt.Fprintf(os.Stderr, "write stdout: %v\n", err)
return 1
}
return 0
}
if err := writeFileAtomic(outPath, resp.Content, 0o644); err != nil {
fmt.Fprintf(os.Stderr, "write %s: %v\n", outPath, err)
return 1
}
return 0
}