package waf

import (
	"strings"

	"github.com/0xseif-code/vexor/internal/httpclient"
)

// signature describes one WAF fingerprint: header substrings (case-insensitive
// matched against response headers), cookie name prefixes, and a server banner
// substring, plus a base confidence and the vendor.
type signature struct {
	name       string
	vendor     string
	baseConf   int
	headerKeys []string // case-insensitive header names that indicate the WAF
	headerVals []string // case-insensitive substrings in any header value
	cookies    []string // cookie name prefixes
	server     string   // substring expected in the Server header
	// bodySigns are substrings in the block body that confirm the WAF.
	bodySigns []string
}

// wafSignatures lists all fingerprint signatures for supported vendors.
var wafSignatures = []signature{
	{
		name:       "Cloudflare",
		vendor:     "Cloudflare",
		baseConf:   90,
		headerKeys: []string{"cf-ray"},
		headerVals: []string{"__cfduid", "cf-cache-status", "cf-ray"},
		cookies:    []string{"__cfduid", "__cf_bm", "cf_clearance"},
		server:     "cloudflare",
	},
	{
		name:       "AWS WAF",
		vendor:     "Amazon Web Services",
		baseConf:   75,
		headerKeys: []string{"x-amzn-requestid", "x-amz-cf-id"},
		headerVals: []string{"awswaf", "x-amz-waf"},
		cookies:    []string{"aws-waf-token"},
		bodySigns:  []string{"Request blocked", "AWS WAF", "x-amzn-RequestId"},
	},
	{
		name:       "Akamai",
		vendor:     "Akamai Technologies",
		baseConf:   80,
		headerKeys: []string{"akamai-x-cache"},
		headerVals: []string{"akamai", "ak_bmsc"},
		server:     "akamaighost",
		bodySigns:  []string{"Reference #", "akamai"},
	},
	{
		name:       "Imperva",
		vendor:     "Imperva / Incapsula",
		baseConf:   85,
		headerVals: []string{"x-cdn: incapsula", "incap_ses", "visid_incap"},
		cookies:    []string{"incap_ses", "visid_incap", "nlbi_"},
		bodySigns:  []string{"Incapsula", "imperva", "Contact Site Administrator"},
	},
	{
		name:       "F5 BIG-IP",
		vendor:     "F5 Networks",
		baseConf:   80,
		headerKeys: []string{"x-wa-info", "f5-sever"},
		cookies:    []string{"BigIP", "F5_ST", "BIGipServer"},
		headerVals: []string{"bigip", "f5-waf", "x-wa-info"},
		bodySigns:  []string{"F5 Networks", "the requested URL was rejected"},
	},
	{
		name:       "Sucuri",
		vendor:     "Sucuri",
		baseConf:   75,
		headerKeys: []string{"x-sucuri-id", "x-sucuri-cache"},
		headerVals: []string{"sucuri"},
		cookies:    []string{"sucuri_cloudproxy"},
		bodySigns:  []string{"Sucuri WebSite Firewall", "Access Denied"},
	},
	{
		name:       "ModSecurity",
		vendor:     "Trustwave ModSecurity",
		baseConf:   65,
		headerVals: []string{"mod_security", "modsecurity"},
		server:     "mod_security",
		bodySigns:  []string{"ModSecurity", "406 Not Acceptable", "Access Denied"},
	},
	{
		name:       "Barracuda",
		vendor:     "Barracuda Networks",
		baseConf:   70,
		cookies:    []string{"barra_counter_session", "BNI__BARRACUDA_LB_COOKIE"},
		headerVals: []string{"barracuda"},
		bodySigns:  []string{"Barracuda", "web application firewall"},
	},
	{
		name:       "Fortinet",
		vendor:     "Fortinet",
		baseConf:   70,
		cookies:    []string{"FORTIWAFSID"},
		headerVals: []string{"fortiwaf", "fortinet"},
		bodySigns:  []string{"FortiWeb", "blocked by fortinet"},
	},
	{
		name:       "Wordfence",
		vendor:     "Wordfence",
		baseConf:   60,
		bodySigns:  []string{"wordfence", "blocked by wordfence", "wf-waf"},
		headerVals: []string{"x-wordfence", "wfut"},
	},
	{
		name:       "Naxsi",
		vendor:     "NBS System / Naxsi",
		baseConf:   65,
		headerKeys: []string{"x-data-origin", "x-naxsi"},
		headerVals: []string{"naxsi"},
		bodySigns:  []string{"naxsi", "blocked by naxsi"},
	},
	{
		name:       "PerimeterX",
		vendor:     "PerimeterX (Human Security)",
		baseConf:   75,
		cookies:    []string{"_px", "px_"},
		headerVals: []string{"perimeterx", "pxhd", "_px"},
		bodySigns:  []string{"PerimeterX", "px-captcha"},
	},
	{
		name:       "Reblaze",
		vendor:     "Reblaze",
		baseConf:   70,
		cookies:    []string{"rbzid", "rbzsessionid"},
		headerVals: []string{"reblaze"},
		bodySigns:  []string{"reblaze", "rbzid"},
	},
}

// passiveMatch inspects an HTTP response and returns every WAF whose
// fingerprint matches, along with the evidence found. It never makes extra
// requests.
func passiveMatch(resp *httpclient.Response) ([]WAF, bool) {
	if resp == nil {
		return nil, false
	}
	var out []WAF
	for _, sig := range wafSignatures {
		evidence := matchSignature(sig, resp)
		if len(evidence) > 0 {
			out = append(out, WAF{
				Name:       sig.name,
				Vendor:     sig.vendor,
				Confidence: scoreConfidence(sig, len(evidence)),
				Evidence:   evidence,
			})
		}
	}
	return out, len(out) > 0
}

// matchSignature returns the evidence strings that match a signature.
func matchSignature(sig signature, resp *httpclient.Response) []string {
	var evidence []string
	server := resp.HeaderGet("Server")
	if sig.server != "" && strings.Contains(strings.ToLower(server), strings.ToLower(sig.server)) {
		evidence = append(evidence, "Server: "+server)
	}

	// Case-insensitive header names.
	for _, key := range sig.headerKeys {
		if v := resp.HeaderGet(key); v != "" {
			evidence = append(evidence, key+": "+v)
		}
	}

	// Substrings in any header value.
	lowerVals := sig.headerVals
	headerValues := allHeaderValues(resp)
	for _, hv := range headerValues {
		lower := strings.ToLower(hv)
		for _, tag := range lowerVals {
			lt := strings.ToLower(tag)
			if strings.Contains(lower, lt) {
				evidence = append(evidence, "header contains \""+tag+"\"")
			}
		}
	}

	// Cookie name prefixes.
	for _, ck := range sig.cookies {
		if hasCookiePrefix(resp, ck) {
			evidence = append(evidence, "cookie \""+ck+"...\"")
		}
	}

	// Body signatures.
	body := strings.ToLower(resp.BodyString())
	for _, bs := range sig.bodySigns {
		if strings.Contains(body, strings.ToLower(bs)) {
			evidence = append(evidence, "body matches \""+bs+"\"")
		}
	}

	return evidence
}

func allHeaderValues(resp *httpclient.Response) []string {
	var out []string
	for _, v := range resp.Headers {
		out = append(out, v)
	}
	return out
}

func hasCookiePrefix(resp *httpclient.Response, prefix string) bool {
	for _, v := range resp.Headers {
		for _, part := range strings.Split(v, ";") {
			part = strings.TrimSpace(part)
			eq := strings.IndexByte(part, '=')
			name := part
			if eq >= 0 {
				name = part[:eq]
			}
			if strings.HasPrefix(strings.ToLower(name), strings.ToLower(prefix)) {
				return true
			}
		}
	}
	return false
}

// scoreConfidence computes a confidence score from the base confidence and the
// number of matched evidence items.
func scoreConfidence(sig signature, evidence int) int {
	score := sig.baseConf
	if evidence >= 3 {
		score += 10
	} else if evidence == 2 {
		score += 5
	}
	if score > 100 {
		score = 100
	}
	return score
}
