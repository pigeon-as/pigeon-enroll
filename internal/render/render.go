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
	"path/filepath"

	"github.com/hashicorp/hcl/v2"
	"github.com/hashicorp/hcl/v2/hclsyntax"
	"github.com/zclconf/go-cty/cty"
)

// File renders a single HCL template file with the given variables.
func File(path string, vars map[string]string) ([]byte, error) {
	src, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read template %s: %w", path, err)
	}

	expr, diags := hclsyntax.ParseTemplate(src, path, hcl.InitialPos)
	if diags.HasErrors() {
		return nil, fmt.Errorf("parse template %s: %s", path, diags.Error())
	}

	ctx := &hcl.EvalContext{
		Variables: make(map[string]cty.Value, len(vars)),
	}
	for k, v := range vars {
		ctx.Variables[k] = cty.StringVal(v)
	}

	val, diags := expr.Value(ctx)
	if diags.HasErrors() {
		return nil, fmt.Errorf("evaluate template %s: %s", path, diags.Error())
	}

	return []byte(val.AsString()), nil
}

// WriteAtomic writes data to path atomically via temp file + rename.
func WriteAtomic(path string, data []byte, perm os.FileMode) error {
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), ".render-*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())

	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Chmod(perm); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), path)
}
