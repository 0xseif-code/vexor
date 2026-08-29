// Package tamper provides payload mutation transforms that evade WAF and
// input-filter rules. Each tamper is a pure function (input string -> output
// string). Tamper chains are applied left-to-right in the order given by the
// user and can be chained for layered evasion.
package tamper

import (
	"errors"
	"fmt"
	"sort"
	"strings"
	"sync"
)

// Tamper is a pure payload transform: input -> mutated output, with no side
// effects.
type Tamper func(payload string) string

// Chain is an ordered list of tampers applied in sequence.
type Chain struct {
	tampers []Tamper
	names   []string
}

// registry holds all registered tampers by canonical (lowercase) name.
var registry = map[string]Tamper{}

// registryOrder tracks insertion order so listing is stable.
var registryOrder []string

var regMu sync.RWMutex

// register adds a tamper to the global registry.
func register(name string, t Tamper) {
	regMu.Lock()
	defer regMu.Unlock()
	key := strings.ToLower(name)
	if _, ok := registry[key]; !ok {
		registryOrder = append(registryOrder, key)
	}
	registry[key] = t
}

func init() {
	// case.go
	register("randomcase", randomcase)
	register("lowercase", lowercase)
	register("uppercase", uppercase)
	register("swapcase", swapcase)

	// comments.go
	register("space2comment", space2comment)
	register("space2hash", space2hash)
	register("space2mysqlblank", space2mysqlblank)
	register("space2plus", space2plus)
	register("versionedmorph", versionedmorph)
	register("versionedkeywords", versionedkeywords)
	register("commentbeforeparen", commentbeforeparen)

	// whitespace.go
	register("space2tab", space2tab)
	register("space2newline", space2newline)
	register("space2randomblank", space2randomblank)
	register("multiplespaces", multiplespaces)
	register("overlongutf8", overlongutf8)

	// encoding.go
	register("charencode", charencode)
	register("chardoubleencode", chardoubleencode)
	register("charunicodeencode", charunicodeencode)
	register("charunicodeescape", charunicodeescape)
	register("base64encode", base64encode)
	register("hex2char", hex2char)
	register("htmlencode", htmlencode)
	register("percentage", percentage)
	register("apostrophenullencode", apostrophenullencode)
	register("apostrophemask", apostrophemask)
	register("equaltolike", equaltolike)
	register("equaltorlike", equaltorlike)
	register("greatest", greatest)
	register("between", between)

	// keywords.go
	register("randomcomments", randomcomments)
	register("modsecurityversioned", modsecurityversioned)
	register("modsecurityzeroversioned", modsecurityzeroversioned)
	register("bluecoat", bluecoat)
	register("halfversionedmorphkeywords", halfversionedmorphkeywords)
	register("unmagicquotes", unmagicquotes)
	register("appendnullbyte", appendnullbyte)
	register("schemasplit", schemasplit)
	register("concat2concatws", concat2concatws)
	register("lowercasekeywords", lowercaseKeywords)
}

// ErrUnknownTamper is returned when a requested tamper is not registered.
var ErrUnknownTamper = errors.New("unknown tamper")

// ListAvailable returns all registered tamper names in deterministic order.
func ListAvailable() []string {
	regMu.RLock()
	defer regMu.RUnlock()
	out := make([]string, 0, len(registryOrder))
	for _, k := range registryOrder {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// GetTamper returns a single tamper by name. Names are case-insensitive.
func GetTamper(name string) (Tamper, error) {
	regMu.RLock()
	t, ok := registry[strings.ToLower(strings.TrimSpace(name))]
	regMu.RUnlock()
	if !ok {
		return nil, fmt.Errorf("%w: %q (available: %s)", ErrUnknownTamper, name, strings.Join(ListAvailable(), ", "))
	}
	return t, nil
}

// isTerminalTamper reports whether a tamper should be applied last in a chain.
// These transforms change the entire payload representation and would break
// any subsequent keyword/comment tamper.
func isTerminalTamper(name string) bool {
	switch strings.ToLower(name) {
	case "base64encode", "chardoubleencode", "charencode",
		"charunicodeencode", "charunicodeescape", "htmlencode":
		return true
	}
	return false
}

// NewChain builds a chain from a comma-separated list of tamper names. It
// validates each name and warns (via an error) when a terminal tamper is not
// last in the chain.
func NewChain(names []string) (*Chain, error) {
	if len(names) == 0 {
		return &Chain{}, nil
	}
	chain := &Chain{}
	var firstErr error
	for i, raw := range names {
		name := strings.TrimSpace(raw)
		if name == "" {
			continue
		}
		t, err := GetTamper(name)
		if err != nil {
			return nil, err
		}
		chain.tampers = append(chain.tampers, t)
		chain.names = append(chain.names, strings.ToLower(name))
		// Compatibility warning: a terminal tamper (e.g. base64encode)
		// that appears before the last position will turn the payload into
		// an opaque blob, making any subsequent keyword/comment tamper
		// ineffective. Surface a warning but still return a usable chain.
		if i < len(names)-1 && isTerminalTamper(name) && firstErr == nil {
			firstErr = fmt.Errorf("warning: tamper %q is best applied LAST in the chain; subsequent tampers on it may be ineffective", name)
		}
	}
	return chain, firstErr
}

// Apply runs every tamper in the chain in order.
func (c *Chain) Apply(payload string) string {
	out := payload
	for _, t := range c.tampers {
		if t != nil {
			out = t(out)
		}
	}
	return out
}

// Names returns the canonical (lowercase) names of the chain's tampers.
func (c *Chain) Names() []string {
	out := make([]string, len(c.names))
	copy(out, c.names)
	return out
}

// Len returns the number of tampers in the chain.
func (c *Chain) Len() int { return len(c.tampers) }

// wafTamperChain maps a detected WAF name to a recommended tamper chain.
// The chains are ordered so comment/case tampers run first and encoding
// tampers run last.
var wafTamperChain = map[string][]string{
	"Cloudflare":    {"space2comment", "randomcase", "charencode"},
	"AWS WAF":       {"space2comment", "randomcase", "chardoubleencode"},
	"Akamai":        {"space2hash", "randomcase", "charencode"},
	"Imperva":       {"space2comment", "randomcase", "charunicodeencode"},
	"Incapsula":     {"space2comment", "randomcase", "charunicodeencode"},
	"F5 BIG-IP":     {"space2comment", "randomcase", "percentage"},
	"Sucuri":        {"space2comment", "charunicodeescape"},
	"ModSecurity":   {"modsecurityversioned", "space2comment", "randomcase"},
	"Barracuda":     {"space2hash", "concat2concatws", "charencode"},
	"Fortinet":      {"space2comment", "randomcase", "unmagicquotes"},
	"Wordfence":     {"space2comment", "randomcase", "hex2char"},
	"Naxsi":         {"space2comment", "charunicodeencode"},
	"PerimeterX":    {"space2comment", "randomcase", "charencode"},
	"Reblaze":       {"space2comment", "randomcase", "chardoubleencode"},
	"BlueCoat":      {"bluecoat", "randomcase"},
	"None detected": {"space2comment", "randomcase"},
}

// SuggestForWAF returns the recommended tamper chain for a detected WAF. The
// WAF name match is case-insensitive and partial.
func SuggestForWAF(wafName string) []string {
	key := strings.ToLower(strings.TrimSpace(wafName))
	if key == "" {
		key = "none detected"
	}
	for name, chain := range wafTamperChain {
		if strings.EqualFold(name, wafName) {
			return append([]string(nil), chain...)
		}
	}
	// Partial match: any WAF whose name is contained in the given string.
	for name, chain := range wafTamperChain {
		if strings.Contains(key, strings.ToLower(name)) {
			return append([]string(nil), chain...)
		}
	}
	return append([]string(nil), wafTamperChain["None detected"]...)
}
