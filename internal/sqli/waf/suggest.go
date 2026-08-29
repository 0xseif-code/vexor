package waf

import (
	"strings"

	"github.com/0xseif-code/vexor/internal/httpclient"
)

// wafTamperChains maps a WAF name to a recommended tamper chain.
var wafTamperChains = map[string][]string{
	"Cloudflare":  {"space2comment", "randomcase", "charencode"},
	"AWS WAF":     {"space2comment", "randomcase", "chardoubleencode"},
	"Akamai":      {"space2hash", "randomcase", "charencode"},
	"Imperva":     {"space2comment", "randomcase", "charunicodeencode"},
	"F5 BIG-IP":   {"space2comment", "randomcase", "percentage"},
	"Sucuri":      {"space2comment", "charunicodeescape"},
	"ModSecurity": {"modsecurityversioned", "space2comment", "randomcase"},
	"Barracuda":   {"space2hash", "concat2concatws", "charencode"},
	"Fortinet":    {"space2comment", "randomcase", "unmagicquotes"},
	"Wordfence":   {"space2comment", "randomcase", "hex2char"},
	"Naxsi":       {"space2comment", "charunicodeencode"},
	"PerimeterX":  {"space2comment", "randomcase", "charencode"},
	"Reblaze":     {"space2comment", "randomcase", "chardoubleencode"},
}

// SuggestedTamperChain returns the recommended tamper chain for a detected WAF
// name. Unknown names fall back to a generic chain.
func SuggestedTamperChain(wafName string) []string {
	key := strings.ToLower(strings.TrimSpace(wafName))
	for name, chain := range wafTamperChains {
		if strings.EqualFold(name, wafName) {
			return append([]string(nil), chain...)
		}
	}
	for name, chain := range wafTamperChains {
		if strings.Contains(key, strings.ToLower(name)) {
			return append([]string(nil), chain...)
		}
	}
	return []string{"space2comment", "randomcase"}
}

// compareResponses looks for a block-response signature by comparing the
// normal and probe responses. If the probe was blocked (distinct status/size)
// but no vendor was fingerprinted, it reports a generic WAF detection with
// evidence describing the block behaviour.
func compareResponses(normal, probe *httpclient.Response, existing []WAF) *WAF {
	if normal == nil || probe == nil {
		return nil
	}
	// If we already identified a WAF, annotate the block there instead of
	// adding a generic entry.
	for i := range existing {
		if probe.StatusCode != normal.StatusCode {
			existing[i].Evidence = append(existing[i].Evidence,
				"blocked probe ("+itoa(probe.StatusCode)+" vs "+itoa(normal.StatusCode)+")")
		}
	}
	if len(existing) > 0 {
		return nil
	}
	if probe.StatusCode != normal.StatusCode && fakeBlockStatus(probe.StatusCode) {
		return &WAF{
			Name:       "Unknown WAF",
			Vendor:     "Unidentified",
			Confidence: 60,
			Evidence: []string{
				"probe " + probeParam + " elicited " + itoa(probe.StatusCode) +
					" vs baseline " + itoa(normal.StatusCode),
			},
		}
	}
	return nil
}

func fakeBlockStatus(code int) bool {
	switch code {
	case 403, 406, 418, 423, 429, 501:
		return true
	}
	return false
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	neg := n < 0
	if neg {
		n = -n
	}
	var digits []byte
	for n > 0 {
		digits = append([]byte{byte('0' + n%10)}, digits...)
		n /= 10
	}
	if neg {
		return "-" + string(digits)
	}
	return string(digits)
}
