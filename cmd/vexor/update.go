package main

import (
	"context"
	"fmt"

	"github.com/0xseif-code/vexor/internal/update"
	"github.com/spf13/cobra"
)

func newUpdateCmd() *cobra.Command {
	var check, force bool
	cmd := &cobra.Command{
		Use:   "update",
		Short: "Update Vexor to the latest release",
		Long: `Update Vexor to the latest GitHub release.

Without flags the binary is updated in place using, in order:
  - go install (rebuild from source), then
  - a platform release asset download, then
  - a git pull + go build from a source clone.
--check only compares the local version against the latest release.
--force reinstalls even when the versions already match.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runUpdate(cmd.Context(), check, force)
		},
	}
	cmd.Flags().BoolVar(&check, "check", false, "only compare local vs latest release (no install)")
	cmd.Flags().BoolVar(&force, "force", false, "reinstall even when versions match")
	return cmd
}

func runUpdate(ctx context.Context, check, force bool) error {
	opts := update.Options{
		CurrentVersion: displayVersion(),
		Force:          force,
		Stdout:         progressWriter(),
	}
	if check {
		tag, err := update.CheckLatest(ctx, opts)
		if err != nil {
			return fmt.Errorf("check update: %w", err)
		}
		cur := update.Normalize(displayVersion())
		latest := update.Normalize(tag)
		switch update.Compare(cur, latest) {
		case 0:
			logOK("Vexor is up to date: v%s", cur)
		case 1:
			logOK("local v%s is newer than the latest release v%s", cur, latest)
		default:
			logWarn("update available: v%s -> v%s (run \"vexor update\" to install)", cur, latest)
		}
		return nil
	}

	res, err := update.Run(ctx, opts)
	if err != nil {
		return err
	}
	if !res.Updated {
		logOK("Vexor is already at the latest version: v%s", res.ToVersion)
		return nil
	}
	logOK("updated v%s -> v%s via %s", res.FromVersion, res.ToVersion, res.Method)
	if res.BinaryPath != "" {
		logInfo("new binary: %s", res.BinaryPath)
	}
	logWarn("restart Vexor to start using the new version")
	return nil
}