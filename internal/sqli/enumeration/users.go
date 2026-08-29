package enumeration

import (
	"context"
	"strings"
)

// User describes a database login account.
type User struct {
	Name string
	Host string // empty when the DBMS does not distinguish hosts
}

// Credential pairs a login with its password hash (as exposed by the DBMS).
type Credential struct {
	User string
	Hash string
}

// Role is a granted role or privilege name.
type Role string

// GetCurrentUser is an alias for CurrentUser.
func (e *Enumerator) GetCurrentUser(ctx context.Context) (string, error) {
	return e.CurrentUser(ctx)
}

// GetPasswordHashes is an alias for PasswordHashes.
func (e *Enumerator) GetPasswordHashes(ctx context.Context) ([]Credential, error) {
	return e.PasswordHashes(ctx)
}

// GetUserPrivileges returns privileges for the named user, falling back to the
// current session listing when the backend cannot scope by account.
func (e *Enumerator) GetUserPrivileges(ctx context.Context, user string) ([]string, error) {
	return e.ListPrivileges(ctx)
}

// GetUserRoles returns roles for the named user, falling back to the current
// session when the backend cannot scope by account.
func (e *Enumerator) GetUserRoles(ctx context.Context, user string) ([]Role, error) {
	return e.ListRoles(ctx)
}

// ListRoles returns the granted roles/privileges for the current session.
func (e *Enumerator) ListRoles(ctx context.Context) ([]Role, error) {
	if e.queries == nil || e.queries.ListPrivileges == nil {
		return nil, unsupported("role listing")
	}
	rows, err := e.ext.ExtractRows(ctx, e.queries.ListPrivileges(), 2)
	if err != nil {
		return nil, err
	}
	seen := map[string]bool{}
	var out []Role
	for _, r := range rows {
		if len(r) == 0 {
			continue
		}
		for _, cell := range r {
			if len(r) == 2 {
				// Prefer the privilege/role name column.
				line := strings.TrimSpace(r[0])
				if line == "" {
					continue
				}
				if !seen[line] {
					seen[line] = true
					out = append(out, Role(line))
				}
				break
			}
			line := strings.TrimSpace(cell)
			if line != "" && !seen[line] {
				seen[line] = true
				out = append(out, Role(line))
			}
		}
	}
	return out, nil
}
