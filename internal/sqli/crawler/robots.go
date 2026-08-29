package crawler

import (
	"bufio"
	"strings"
)

// parseRobots pulls Disallow paths out of a robots.txt body. It merges rules
// conservatively across all user agents and ignores Allow directives and
// comments.
func parseRobots(body string) []string {
	var disallowed []string
	scanner := bufio.NewScanner(strings.NewReader(body))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		lower := strings.ToLower(line)
		switch {
		case strings.HasPrefix(lower, "user-agent"):
			// We intentionally do not scope disallow rules to a single agent;
			// we merge all disallow rules conservatively.
			continue
		case strings.HasPrefix(lower, "disallow"):
			value := strings.TrimSpace(strings.TrimPrefix(strings.TrimPrefix(line, "Disallow:"), "disallow:"))
			value = trimInlineComment(value)
			if value != "" {
				disallowed = append(disallowed, value)
			}
		}
	}
	return disallowed
}

func trimInlineComment(s string) string {
	if idx := strings.Index(s, "#"); idx >= 0 {
		return strings.TrimSpace(s[:idx])
	}
	return strings.TrimSpace(s)
}
