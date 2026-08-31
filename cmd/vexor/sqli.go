package main

import (
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"syscall"

	"github.com/fatih/color"
	"github.com/spf13/cobra"
)

var sqliLongHelp = `vexor sqli - SQL injection testing (delegates to sqlmap)

This is a thin wrapper around sqlmap, the industry-standard SQL injection tool.
Vexor does not ship its own SQLi engine. sqlmap must be installed and on PATH.

Examples:
  vexor sqli -u "https://target/item?id=1"
  vexor sqli -u "https://target/item?id=1" --dbs
  vexor sqli -u "https://target/item?id=1" -D app --tables
  vexor sqli -u "https://target/item?id=1" -D app -T users --dump
  vexor sqli -r request.txt --dump --batch
  vexor sqli -u "https://target/item?id=1" --tamper=space2comment --level 3`

func newSQLiCmd() *cobra.Command {
	var (
		url      string
		request  string
		param    string
		database string
		table    string
		columns  []string
		data     string
		cookie   string
		headers  []string
		proxy    string
		level    int
		risk     int
		threads  int
		technique string
		dbms     string
		dbs      bool
		tables   bool
		colscan  bool
		dump     bool
		curUser  bool
		curDB    bool
		isDBA    bool
		passwords bool
		batch     bool
		randAgent bool
		tamper    string
		forms     bool
		crawl     int
		osShell   bool
		sqlShell  bool
		extra     []string
	)

	cmd := &cobra.Command{
		Use:   "sqli",
		Short: "SQL injection testing (delegates to sqlmap)",
		Long:  sqliLongHelp,
		Args:  cobra.ArbitraryArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			sqlmapBin, err := exec.LookPath("sqlmap")
			if err != nil {
				fmt.Fprintln(os.Stderr, color.RedString("[!] sqlmap is not installed on this system."))
				fmt.Fprintln(os.Stderr)
				fmt.Fprintln(os.Stderr, color.CyanString("[i] Install it with one of:"))
				fmt.Fprintln(os.Stderr, "    Debian/Kali:  sudo apt install sqlmap")
				fmt.Fprintln(os.Stderr, "    Arch:         sudo pacman -S sqlmap")
				fmt.Fprintln(os.Stderr, "    pipx:         pipx install sqlmap")
				fmt.Fprintln(os.Stderr, "    Manual:       https://github.com/sqlmapproject/sqlmap")
				return fmt.Errorf("sqlmap not found")
			}

			if url == "" && request == "" {
				return cmd.Help()
			}

			target := url
			if request != "" {
				target = request + " (raw request)"
			}
			fmt.Fprintf(os.Stderr, "%s delegating to sqlmap: %s\n",
				color.CyanString("[*]"), sqlmapBin)
			fmt.Fprintf(os.Stderr, "%s target: %s\n",
				color.CyanString("[*]"), target)

			sqlmapArgs := buildSqlmapArgs(url, request, param, database, table, columns,
				data, cookie, headers, proxy, level, risk, threads, technique, dbms,
				dbs, tables, colscan, dump, curUser, curDB, isDBA, passwords,
				batch, randAgent, tamper, forms, crawl, osShell, sqlShell, extra)

			return runSqlmap(cmd, sqlmapBin, sqlmapArgs)
		},
	}

	f := cmd.Flags()
	f.StringVarP(&url, "url", "u", "", "target URL, e.g. https://example.com/page?id=1")
	f.StringVarP(&request, "request", "r", "", "Burp-style raw HTTP request file")
	f.StringVarP(&param, "param", "p", "", "only test this parameter")
	f.StringVarP(&database, "database", "D", "", "database name for --tables/--columns/--dump")
	f.StringVarP(&table, "table", "T", "", "table name for --columns/--dump")
	f.StringSliceVarP(&columns, "column", "C", nil, "specific columns to dump (repeatable)")
	f.StringVar(&data, "data", "", "POST data string")
	f.StringVar(&cookie, "cookie", "", "HTTP cookie header value")
	f.StringArrayVar(&headers, "headers", nil, `custom HTTP header (repeatable), e.g. -H "User-Agent: sqlmap"`)
	f.StringVar(&proxy, "proxy", "", "HTTP/SOCKS5 proxy URL")
	f.IntVar(&level, "level", 1, "test intensity level (1-5)")
	f.IntVar(&risk, "risk", 1, "risk level for payloads (1-3)")
	f.IntVar(&threads, "threads", 5, "concurrent requests")
	f.StringVar(&technique, "technique", "", "SQLi techniques to test: BEUSTQ")
	f.StringVar(&dbms, "dbms", "", "force DBMS type: mysql, postgresql, mssql, etc.")
	f.BoolVar(&dbs, "dbs", false, "enumerate databases")
	f.BoolVar(&tables, "tables", false, "enumerate tables")
	f.BoolVar(&colscan, "columns", false, "enumerate columns")
	f.BoolVar(&dump, "dump", false, "dump table entries")
	f.BoolVar(&curUser, "current-user", false, "enumerate current DBMS user")
	f.BoolVar(&curDB, "current-db", false, "enumerate current database")
	f.BoolVar(&isDBA, "is-dba", false, "check DBA privileges")
	f.BoolVar(&passwords, "passwords", false, "enumerate password hashes")
	f.BoolVar(&batch, "batch", true, "never ask for user input")
	f.BoolVar(&randAgent, "random-agent", true, "use a random HTTP User-Agent")
	f.StringVar(&tamper, "tamper", "", "tamper script(s)")
	f.BoolVar(&forms, "forms", false, "parse and test forms on target URL")
	f.IntVar(&crawl, "crawl", 0, "crawl depth for target URL")
	f.BoolVar(&osShell, "os-shell", false, "prompt for an interactive OS shell")
	f.BoolVar(&sqlShell, "sql-shell", false, "prompt for an interactive SQL shell")
	f.StringSliceVar(&extra, "extra", nil, "extra raw arguments passed directly to sqlmap")

	return cmd
}

func buildSqlmapArgs(url, request, param, database, table string, columns []string,
	data, cookie string, headers []string, proxy string,
	level, risk, threads int, technique, dbms string,
	dbs, tables, colscan, dump, curUser, curDB, isDBA, passwords bool,
	batch, randAgent bool, tamper string, forms bool, crawl int,
	osShell, sqlShell bool, extra []string) []string {

	var args []string

	if url != "" {
		args = append(args, "-u", url)
	}
	if request != "" {
		args = append(args, "-r", request)
	}
	if param != "" {
		args = append(args, "-p", param)
	}
	if database != "" {
		args = append(args, "-D", database)
	}
	if table != "" {
		args = append(args, "-T", table)
	}
	for _, c := range columns {
		args = append(args, "-C", c)
	}
	if data != "" {
		args = append(args, "--data", data)
	}
	if cookie != "" {
		args = append(args, "--cookie", cookie)
	}
	for _, h := range headers {
		args = append(args, "-H", h)
	}
	if proxy != "" {
		args = append(args, "--proxy", proxy)
	}
	if level != 1 {
		args = append(args, "--level", fmt.Sprintf("%d", level))
	}
	if risk != 1 {
		args = append(args, "--risk", fmt.Sprintf("%d", risk))
	}
	if threads != 5 {
		args = append(args, "--threads", fmt.Sprintf("%d", threads))
	}
	if technique != "" {
		args = append(args, "--technique", technique)
	}
	if dbms != "" {
		args = append(args, "--dbms", dbms)
	}
	if dbs {
		args = append(args, "--dbs")
	}
	if tables {
		args = append(args, "--tables")
	}
	if colscan {
		args = append(args, "--columns")
	}
	if dump {
		args = append(args, "--dump")
	}
	if curUser {
		args = append(args, "--current-user")
	}
	if curDB {
		args = append(args, "--current-db")
	}
	if isDBA {
		args = append(args, "--is-dba")
	}
	if passwords {
		args = append(args, "--passwords")
	}
	if batch {
		args = append(args, "--batch")
	}
	if randAgent {
		args = append(args, "--random-agent")
	}
	if tamper != "" {
		args = append(args, "--tamper", tamper)
	}
	if forms {
		args = append(args, "--forms")
	}
	if crawl > 0 {
		args = append(args, "--crawl", fmt.Sprintf("%d", crawl))
	}
	if osShell {
		args = append(args, "--os-shell")
	}
	if sqlShell {
		args = append(args, "--sql-shell")
	}
	args = append(args, extra...)
	return args
}

func runSqlmap(cmd *cobra.Command, bin string, args []string) error {
	ctx := cmd.Context()

	// Ctrl+C goes to the child process (sqlmap).
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)
	defer signal.Stop(sigCh)

	c := exec.CommandContext(ctx, bin, args...)
	c.Stdin = os.Stdin
	c.Stdout = os.Stdout
	c.Stderr = os.Stderr

	if err := c.Start(); err != nil {
		return fmt.Errorf("failed to start sqlmap: %w", err)
	}

	// Forward signals to the child process.
	go func() {
		for {
			select {
			case <-ctx.Done():
				return
			case sig := <-sigCh:
				if c.Process != nil {
					c.Process.Signal(sig)
				}
			}
		}
	}()

	err := c.Wait()
	if err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			os.Exit(exitErr.ExitCode())
		}
		return err
	}
	return nil
}
