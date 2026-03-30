package render

import (
	"fmt"

	"github.com/hashicorp/hcl/v2/hclsimple"
)

// Config holds the render configuration.
type Config struct {
	Templates []Template `hcl:"template,block"`
}

// Template defines a single template rendering spec.
type Template struct {
	Source      string `hcl:"source,optional"`
	Content     string `hcl:"content,optional"`
	Destination string `hcl:"destination"`
	Perms       string `hcl:"perms,optional"`
	User        string `hcl:"user,optional"`
	Group       string `hcl:"group,optional"`
}

// LoadConfig reads a render HCL config file.
func LoadConfig(path string) (Config, error) {
	var cfg Config
	if err := hclsimple.DecodeFile(path, nil, &cfg); err != nil {
		return Config{}, err
	}
	for i, t := range cfg.Templates {
		if t.Source == "" && t.Content == "" {
			return Config{}, fmt.Errorf("template[%d]: source or content is required", i)
		}
		if t.Source != "" && t.Content != "" {
			return Config{}, fmt.Errorf("template[%d]: source and content are mutually exclusive", i)
		}
	}
	return cfg, nil
}
