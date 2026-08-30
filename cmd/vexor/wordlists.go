package main

import (
	"context"
	"fmt"
	"os"
	"time"

	"github.com/0xseif-code/vexor/internal/wordlists"
	"github.com/spf13/cobra"
)

func newWordlistsCmd() *cobra.Command {
	return &cobra.Command{
		Use:     "update-wordlists",
		Aliases: []string{"wordlists"},
		Short:   "Re-download and verify all cached SecLists wordlists",
		Long: `Force a full re-download and integrity verification of every wordlist
in the cached SecLists mirror, overwriting previously cached files.

The cache lives in ~/.vexor/wordlists. Progress is reported on stderr
unless --silent is active.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runUpdateWordlists(cmd.Context())
		},
	}
}

func runUpdateWordlists(ctx context.Context) error {
	start := time.Now()

	m, err := wordlists.NewManager()
	if err != nil {
		return err
	}
	if !app.silent {
		m.SetProgressCallback(func(downloaded, total int64) {
			if total > 0 {
				fmt.Fprintf(os.Stderr, "\r[*] downloading... %6.2f%% (%s/%s)", float64(downloaded)/float64(total)*100, humanSize(downloaded), humanSize(total))
			} else {
				fmt.Fprintf(os.Stderr, "\r[*] downloading... %s", humanSize(downloaded))
			}
		})
	}

	logInfo("re-downloading all wordlists into %s", m.CacheDir())
	if err := m.Update(ctx); err != nil {
		if !app.silent {
			fmt.Fprintln(os.Stderr)
		}
		return err
	}
	if !app.silent {
		fmt.Fprintln(os.Stderr)
	}

	files, err := m.Stats()
	if err != nil {
		return err
	}
	logOK("wordlist cache updated: %d files in %s", len(files), humanDur(time.Since(start)))
	for _, f := range files {
		hash := f.SHA256
		if len(hash) > 12 {
			hash = hash[:12]
		}
		logInfo("  %s/%s  %-10s  sha256=%s", f.Category, f.Size, humanSize(f.Bytes), hash)
	}
	return nil
}
