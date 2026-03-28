package render

import (
	"fmt"
	"os/user"
	"strconv"
)

// LookupUser resolves a username or numeric UID to a numeric UID.
// Returns -1 if s is empty.
func LookupUser(s string) (int, error) {
	if s == "" {
		return -1, nil
	}
	if id, err := strconv.Atoi(s); err == nil {
		return id, nil
	}
	u, err := user.Lookup(s)
	if err != nil {
		return 0, fmt.Errorf("lookup user %q: %w", s, err)
	}
	return strconv.Atoi(u.Uid)
}

// LookupGroup resolves a group name or numeric GID to a numeric GID.
// Returns -1 if s is empty.
func LookupGroup(s string) (int, error) {
	if s == "" {
		return -1, nil
	}
	if id, err := strconv.Atoi(s); err == nil {
		return id, nil
	}
	g, err := user.LookupGroup(s)
	if err != nil {
		return 0, fmt.Errorf("lookup group %q: %w", s, err)
	}
	return strconv.Atoi(g.Gid)
}
