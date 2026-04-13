package main

import (
	"fmt"
	"os"
	"strconv"

	"github.com/pigeon-as/pigeon-enroll/internal/atomicfile"
	"github.com/pigeon-as/pigeon-enroll/internal/render"
)

func cmdRender(args []string) int {
	flags := newFlagSet("render")
	configPath := flags.String("config", "", "Path to render HCL config")
	varsPath := flags.String("vars", "/var/lib/pigeon/enroll.json", "Path to template variables JSON")
	flags.Parse(args)

	if *configPath == "" {
		fmt.Fprintln(os.Stderr, "usage: pigeon-enroll render -config=<path> [-vars=<path>]")
		return 1
	}

	cfg, err := render.LoadConfig(*configPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "load render config: %v\n", err)
		return 1
	}

	vars, err := render.ParseVarsFile(*varsPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "parse vars: %v\n", err)
		return 1
	}

	for _, tpl := range cfg.Templates {
		perms := tpl.Perms
		if perms == "" {
			perms = "0640"
		}
		perm, err := parsePerms(perms)
		if err != nil {
			fmt.Fprintf(os.Stderr, "invalid perms for %s: %v\n", tpl.Destination, err)
			return 1
		}

		var rendered []byte
		if tpl.Content != "" {
			rendered, err = render.Content(tpl.Content, vars)
		} else {
			rendered, err = render.File(tpl.Source, vars)
		}
		if err != nil {
			fmt.Fprintf(os.Stderr, "render %s: %v\n", tpl.Destination, err)
			return 1
		}

		uid, err := render.LookupUser(tpl.User)
		if err != nil {
			fmt.Fprintf(os.Stderr, "%s: %v\n", tpl.Destination, err)
			return 1
		}
		gid, err := render.LookupGroup(tpl.Group)
		if err != nil {
			fmt.Fprintf(os.Stderr, "%s: %v\n", tpl.Destination, err)
			return 1
		}

		if err := atomicfile.WriteOwned(tpl.Destination, rendered, perm, uid, gid); err != nil {
			fmt.Fprintf(os.Stderr, "write %s: %v\n", tpl.Destination, err)
			return 1
		}

		if tpl.Source != "" {
			fmt.Fprintf(os.Stderr, "rendered %s → %s\n", tpl.Source, tpl.Destination)
		} else {
			fmt.Fprintf(os.Stderr, "rendered → %s\n", tpl.Destination)
		}
	}

	return 0
}

func parsePerms(s string) (os.FileMode, error) {
	p, err := strconv.ParseUint(s, 8, 32)
	if err != nil {
		return 0, fmt.Errorf("parse perms %q: %w", s, err)
	}
	if p > 0o777 {
		return 0, fmt.Errorf("invalid perms %q: must be between 0000 and 0777", s)
	}
	return os.FileMode(p), nil
}
