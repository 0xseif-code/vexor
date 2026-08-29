package main

import (
	"context"
	"fmt"
	"os"
	"runtime"

	"github.com/spf13/cobra"
)

func newVersionCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "version",
		Short: "Print Vexor version, build info, and banner",
		Long: `Print Vexor version, build info, and the banner.

The banner is suppressed when --silent is active.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runVersion(cmd.Context())
		},
	}
}

func runVersion(_ context.Context) error {
	if !app.silent {
		printBanner()
	}
	fmt.Fprintf(os.Stdout, "Vexor v%s\n", Version)
	fmt.Fprintf(os.Stdout, "Version:   %s\n", Version)
	fmt.Fprintf(os.Stdout, "Build:     %s\n", BuildDate)
	fmt.Fprintf(os.Stdout, "Go:        %s\n", runtime.Version())
	return nil
}
