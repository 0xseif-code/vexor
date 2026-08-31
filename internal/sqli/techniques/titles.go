package techniques

import (
	"strings"

	"github.com/0xseif-code/vexor/internal/sqli/dbms"
	"github.com/0xseif-code/vexor/internal/sqli/ui"
)

// familyTitle builds a sqlmap-style title for a payload family, e.g.
// "MySQL boolean-based blind - WHERE clause" or
// "PostgreSQL error-based - CAST error".
func familyTitle(p *dbms.Payloads, technique, clause string) string {
	if p == nil {
		return ""
	}
	base := p.Title()
	if base == "" {
		base = p.Name
	}
	return base + " " + technique + " - " + clause
}

// logTesting emits a real-time [HH:MM:SS] [INFO] "testing '<title>'" line so
// the operator sees which payload family is being tried without waiting for
// the whole batch to complete.
func logTesting(title string) {
	if strings.TrimSpace(title) == "" {
		return
	}
	ui.Infof("testing '%s'", title)
}

// clauseFromPayload names the specific clause / error function a confirmed
// payload uses, so the summary box can go beyond the generic family name.
func clauseFromPayload(payload string) string {
	up := strings.ToUpper(payload)
	switch {
	case strings.Contains(up, "EXTRACTVALUE"):
		return "(EXTRACTVALUE)"
	case strings.Contains(up, "UPDATEXML"):
		return "(UPDATEXML)"
	case strings.Contains(up, "GTID_SUBSET"):
		return "(GTID_SUBSET)"
	case strings.Contains(up, "NAME_CONST"):
		return "(NAME_CONST)"
	case strings.Contains(up, "FLOOR(RAND") || strings.Contains(up, "COUNT(*),"):
		return "(FLOOR)"
	case strings.Contains(up, "BENCHMARK"):
		return "(BENCHMARK)"
	case strings.Contains(up, "PG_SLEEP"):
		return "pg_sleep"
	case strings.Contains(up, "WAITFOR"):
		return "(WAITFOR DELAY)"
	case strings.Contains(up, "SLEEP"):
		return "(SLEEP)"
	case strings.Contains(up, "CAST(("):
		return "(CAST)"
	case strings.Contains(up, "CONVERT"):
		return "(CONVERT)"
	case strings.Contains(up, "ORDER BY"):
		return "ORDER BY clause"
	case strings.Contains(up, "UNION"):
		return "UNION query"
	default:
		return "payload"
	}
}

// booleanClause returns the WHERE/HAVING-style label used in boolean/inline
// titles.
func booleanClause() string { return "WHERE clause" }
