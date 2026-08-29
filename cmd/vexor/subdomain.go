package main

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/0xseif-code/vexor/internal/enum/subdomain"
	"github.com/0xseif-code/vexor/internal/wordlists"
	"github.com/spf13/cobra"
)

func newSubdomainCmd() *cobra.Command {
	var (
		domain, list, sizeWordlist, wordlist string
		resolvers                            []string
		activeOnly, passiveOnly              bool
	)

	cmd := &cobra.Command{
		Use:   "subdomain",
		Short: "Enumerate subdomains",
		Long: `Enumerate subdomains using active DNS brute-forcing and passive
certificate-transparency (crt.sh) lookups, deduplicating results across
both sources. Targets are taken from -d or a newline-delimited file.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runSubdomain(cmd.Context(), domain, list, sizeWordlist, wordlist, resolvers, activeOnly, passiveOnly)
		},
	}

	f := cmd.Flags()
	f.StringVarP(&domain, "domain", "d", "", "target domain (required unless --list is used)")
	f.StringVarP(&list, "list", "l", "", "file containing target domains, one per line")
	f.StringVarP(&sizeWordlist, "size", "s", "medium", "wordlist size: small, medium, large")
	f.StringVarP(&wordlist, "wordlist", "w", "", "custom wordlist path (overrides --size)")
	f.StringArrayVar(&resolvers, "resolvers", nil, "custom DNS resolvers, repeatable, e.g. --resolvers 8.8.8.8:853")
	f.BoolVar(&activeOnly, "active-only", false, "run only DNS brute-force, skip crt.sh")
	f.BoolVar(&passiveOnly, "passive-only", false, "run only crt.sh, skip DNS brute-force")

	return cmd
}

func runSubdomain(ctx context.Context, domain, list, sizeWordlist, wordlist string, resolvers []string, activeOnly, passiveOnly bool) error {
	start := time.Now()

	domains, err := targetDomains(domain, list)
	if err != nil {
		return err
	}
	if activeOnly && passiveOnly {
		return fmt.Errorf("--active-only and --passive-only cannot be used together")
	}
	if wordlist != "" {
		if _, err := os.Stat(wordlist); err != nil {
			return fmt.Errorf("custom wordlist: %w", err)
		}
		sizeWordlist = ""
	}

	client, err := newHTTPClient()
	if err != nil {
		return err
	}
	selector, err := newSelector()
	if err != nil {
		return err
	}
	pub, err := newPublisher(app.format, app.output)
	if err != nil {
		return err
	}
	defer pub.Close()

	mode := "dns+crtsh"
	if activeOnly {
		mode = "dns"
	}
	if passiveOnly {
		mode = "crtsh"
	}
	logStep("starting subdomain enumeration: %s (mode=%s, threads=%d, size=%s)", strings.Join(domains, ", "), mode, threads(), sizeWordlist)

	header := []string{"subdomain", "ips", "source", "cname"}
	total := 0
	for _, d := range domains {
		cfg := subdomain.Config{
			Domain:      d,
			Resolvers:   resolvers,
			Concurrency: threads(),
			Timeout:     timeoutDur(),
			ActiveOnly:  activeOnly,
			PassiveOnly: passiveOnly,
			WordlistOpts: wordlists.Options{
				Category:   wordlists.CategorySubdomain,
				Size:       wordlists.Size(sizeWordlist),
				CustomPath: wordlist,
			},
		}

		enum := subdomain.New(cfg, client, selector)
		resCh, errCh := enum.Run(ctx)

		for r := range resCh {
			total++
			pub.Publish(
				r.Subdomain,
				struct {
					Subdomain string   `json:"subdomain"`
					IPs       []string `json:"ips"`
					Source    string   `json:"source"`
					CNAME     string   `json:"cname"`
				}{r.Subdomain, r.IPs, r.Source, r.CNAME},
				header,
				[]string{r.Subdomain, strings.Join(r.IPs, ","), r.Source, r.CNAME},
			)
		}
		for err := range errCh {
			logWarn("subdomain: %v", err)
		}

		st := enum.Stats()
		logOK("domain %s: %d subdomains (dns=%d, crtsh=%d) in %s", d, st.Found, st.FromDNS, st.FromCRTSH, humanDur(st.Duration))
		if st.ActiveErr != nil {
			logWarn("DNS engine: %v", st.ActiveErr)
		}
		if st.PassiveErr != nil {
			logWarn("crtsh engine: %v", st.PassiveErr)
		}
	}

	logOK("subdomain enumeration complete: %d total subdomains in %s", total, humanDur(time.Since(start)))
	return nil
}

// targetDomains collects unique domains from -d and the -l file.
func targetDomains(domain, list string) ([]string, error) {
	var out []string
	seen := make(map[string]bool)
	add := func(d string) {
		d = strings.TrimSpace(strings.ToLower(d))
		if d != "" && !seen[d] {
			seen[d] = true
			out = append(out, d)
		}
	}
	if domain != "" {
		add(domain)
	}
	if list != "" {
		fh, err := os.Open(list)
		if err != nil {
			return nil, fmt.Errorf("open domain list %s: %w", list, err)
		}
		defer fh.Close()
		sc := bufio.NewScanner(fh)
		for sc.Scan() {
			line := strings.TrimSpace(sc.Text())
			if line == "" || strings.HasPrefix(line, "#") {
				continue
			}
			add(line)
		}
		if err := sc.Err(); err != nil {
			return nil, fmt.Errorf("read domain list %s: %w", list, err)
		}
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("no target domain: set -d or -l")
	}
	return out, nil
}
