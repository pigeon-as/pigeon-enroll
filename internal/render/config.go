package render

import "github.com/hashicorp/hcl/v2/hclsimple"

// Config holds the render configuration.
type Config struct {
	Templates []Template `hcl:"template,block"`
}

// Template defines a single template rendering spec.
type Template struct {
	Source      string `hcl:"source"`
	Destination string `hcl:"destination"`
	Perms       string `hcl:"perms,optional"`
}

// LoadConfig reads a render HCL config file.
func LoadConfig(path string) (Config, error) {
	var cfg Config
	if err := hclsimple.DecodeFile(path, nil, &cfg); err != nil {
		return Config{}, err
	}
	return cfg, nil
}
