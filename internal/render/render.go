// Package render provides one-shot HCL template rendering using the same
// hclsyntax.ParseTemplate engine that Terraform's templatefile() uses.
//
// Template syntax: ${var} for interpolation, %{if}/%{for} for directives.
// Go template {{ }} delimiters pass through as literal text — zero collision
// by design, since HCL's template language ignores them.
package render

import (
	"fmt"
	"os"

	"github.com/hashicorp/hcl/v2"
	"github.com/hashicorp/hcl/v2/hclsyntax"
	"github.com/pigeon-as/pigeon-enroll/internal/atomicfile"
	"github.com/zclconf/go-cty/cty"
	ctyjson "github.com/zclconf/go-cty/cty/json"
)

// File renders a single HCL template file with the given variables.
// Variables can be strings or nested objects, like Terraform's templatefile().
func File(path string, vars map[string]cty.Value) ([]byte, error) {
	src, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read template %s: %w", path, err)
	}
	return eval(src, path, vars)
}

// Content renders an inline HCL template string with the given variables.
func Content(content string, vars map[string]cty.Value) ([]byte, error) {
	return eval([]byte(content), "inline", vars)
}

func eval(src []byte, filename string, vars map[string]cty.Value) ([]byte, error) {
	expr, diags := hclsyntax.ParseTemplate(src, filename, hcl.InitialPos)
	if diags.HasErrors() {
		return nil, fmt.Errorf("parse template %s: %s", filename, diags.Error())
	}

	ctx := &hcl.EvalContext{Variables: vars}

	val, diags := expr.Value(ctx)
	if diags.HasErrors() {
		return nil, fmt.Errorf("evaluate template %s: %s", filename, diags.Error())
	}

	return []byte(val.AsString()), nil
}

// ParseVarsJSON reads a JSON file and converts it to cty values for use as
// template variables. Uses go-cty's built-in JSON → cty type inference
// (the same approach as Terraform's templatefile).
func ParseVarsJSON(data []byte) (map[string]cty.Value, error) {
	ty, err := ctyjson.ImpliedType(data)
	if err != nil {
		return nil, fmt.Errorf("infer type: %w", err)
	}
	val, err := ctyjson.Unmarshal(data, ty)
	if err != nil {
		return nil, fmt.Errorf("unmarshal: %w", err)
	}
	if !val.Type().IsObjectType() {
		return nil, fmt.Errorf("vars must be a JSON object, got %s", val.Type().FriendlyName())
	}
	return val.AsValueMap(), nil
}

// ParseVarsFile reads a JSON file from disk and converts it to template variables.
func ParseVarsFile(path string) (map[string]cty.Value, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	// Reject empty files. An empty JSON file is not a valid vars object but
	// json.Decoder would report a confusing "EOF" error.
	data = trimJSONWhitespace(data)
	if len(data) == 0 {
		return nil, nil
	}
	return ParseVarsJSON(data)
}

func trimJSONWhitespace(b []byte) []byte {
	for len(b) > 0 && (b[0] == ' ' || b[0] == '\t' || b[0] == '\n' || b[0] == '\r') {
		b = b[1:]
	}
	for len(b) > 0 && (b[len(b)-1] == ' ' || b[len(b)-1] == '\t' || b[len(b)-1] == '\n' || b[len(b)-1] == '\r') {
		b = b[:len(b)-1]
	}
	return b
}

// WriteAtomic writes data to path atomically via temp file + rename.
// Ownership is set on the temp file before rename, so the destination
// appears with correct ownership atomically.
func WriteAtomic(path string, data []byte, perm os.FileMode, uid, gid int) error {
	return atomicfile.WriteOwned(path, data, perm, uid, gid)
}
