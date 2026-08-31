// Package fingerprint extracts an identification of the stack behind an
// injection point: the web server and its operating system from the Server
// header, the application technology from X-Powered-By, and the back-end DBMS
// from both error-based extraction and the Server banner. It never probes for
// its own sake; it reads already-captured baseline responses and a single
// DBMS version string.
package fingerprint

import (
	"regexp"
	"strings"

	"github.com/0xseif-code/vexor/internal/httpclient"
)

// TechFingerprint is the aggregate technology identification for a target.
type TechFingerprint struct {
	// WebServer is the product and version from the Server header, e.g.
	// "Apache/2.2.15" or "nginx/1.18.0".
	WebServer string
	// OS is the operating system as reported by Server or the DBMS compile OS,
	// e.g. "Linux Fedora" or "Win64".
	OS string
	// AppTech is the application runtime from X-Powered-By, e.g. "PHP/5.3.3".
	AppTech string
	// DBMSFull is the full version banner, e.g. "MySQL 5.1.41-community".
	DBMSFull string
	// DBMSShort is the shortened family + major.minor, e.g. "MySQL >= 5.1".
	DBMSShort string
}

// Server- and power-by header keys read from a captured response.
var serverToken = regexp.MustCompile(`(?i)^([a-z]+(?:/[0-9.]+)?)`)

// FromResponse fills the web server, OS and app-tech fields from an HTTP
// response's Server / X-Powered-By headers. It is safe to call with a nil
// response and mutates the receiver in place, leaving unknown fields empty.
func (t *TechFingerprint) FromResponse(resp *httpclient.Response) {
	if resp == nil {
		return
	}
	t.WebServer = extractWebServer(resp.HeaderGet("Server"))
	t.OS = extractOS(resp.HeaderGet("Server"))
	t.AppTech = extractAppTech(resp.HeaderGet("X-Powered-By"))
}

// extractWebServer splits the Server banner ("Apache/2.2.15 (Fedora)") into the
// product/version ("Apache/2.2.15").
func extractWebServer(server string) string {
	server = strings.TrimSpace(server)
	if server == "" {
		return ""
	}
	return strings.TrimSpace(serverToken.FindString(server))
}

// extractOS picks the operating-system hint out of a Server banner. The
// parenthesised trail " (Fedora)" maps to "Linux Fedora"; a lone "Ubuntu" /
// "Debian" token implies its Linux distribution.
func extractOS(server string) string {
	server = strings.TrimSpace(server)
	if server == "" {
		return ""
	}
	if i := strings.Index(server, "("); i >= 0 {
		rest := server[i+1:]
		if j := strings.Index(rest, ")"); j >= 0 {
			name := strings.TrimSpace(rest[:j])
			if strings.EqualFold(name, "Ubuntu") || strings.EqualFold(name, "Debian") ||
				strings.EqualFold(name, "Fedora") || strings.EqualFold(name, "Red") {
				return "Linux " + name
			}
			return name
		}
	}
	lower := strings.ToLower(server)
	switch {
	case strings.Contains(lower, "ubuntu"):
		return "Linux Ubuntu"
	case strings.Contains(lower, "debian"):
		return "Linux Debian"
	case strings.Contains(lower, "fedora"):
		return "Linux Fedora"
	case strings.Contains(lower, "centos"):
		return "Linux CentOS"
	case strings.Contains(lower, "win"):
		return "Windows"
	case strings.Contains(lower, "freebsd"):
		return "FreeBSD"
	case strings.Contains(lower, "darwin"), strings.Contains(lower, "macos"):
		return "macOS"
	}
	return ""
}

// extractAppTech returns the technology token from X-Powered-By
// ("PHP/5.3.3" -> "PHP/5.3.3"), keeping the whole value.
func extractAppTech(poweredBy string) string {
	return strings.TrimSpace(poweredBy)
}

// DBMS-version parsing for error-based extraction.
var versionBanner = regexp.MustCompile(`(?i)(mysql|mariadb)[^0-9]*([0-9]+\.[0-9]+(?:\.[0-9]+)?)`)

// FromDBMSVersion fills the DBMS fields from a version banner pulled out of an
// error-based extraction (e.g. "5.1.41-community"). When the banner does not
// name the product it is assumed MySQL, matching the error-based MySQL context
// it was extracted from.
func (t *TechFingerprint) FromDBMSVersion(version string) {
	version = strings.TrimSpace(version)
	if version == "" {
		return
	}
	t.DBMSFull = version
	if m := versionBanner.FindStringSubmatch(version); m != nil {
		t.DBMSFull = m[1] + " " + m[2]
		t.DBMSShort = m[1] + " >= " + majorMinor(m[2])
		return
	}
	// Bare version (the query returned only numbers): assume MySQL.
	if m := regexp.MustCompile(`([0-9]+\.[0-9]+)`).FindStringSubmatch(version); m != nil {
		t.DBMSShort = "MySQL >= " + m[1]
		t.DBMSFull = "MySQL " + version
		return
	}
	t.DBMSShort = "MySQL"
	if t.DBMSFull == "" {
		t.DBMSFull = "MySQL"
	}
}

// majorMinor reduces a dotted version to its first two components ("5.1.41" ->
// "5.1"), so short labels read "MySQL >= 5.1".
func majorMinor(v string) string {
	if i := strings.IndexByte(v, '.'); i >= 0 {
		if j := strings.IndexByte(v[i+1:], '.'); j >= 0 {
			return v[:i+j+1]
		}
	}
	return v
}

// FromDBMSCompileOS fills the OS field from a `SELECT @@version_compile_os`
// extraction ("Win64" / "Linux").
func (t *TechFingerprint) FromDBMSCompileOS(compileOS string) {
	compileOS = strings.TrimSpace(compileOS)
	if compileOS == "" {
		return
	}
	switch {
	case strings.HasPrefix(strings.ToLower(compileOS), "win"):
		t.OS = "Windows"
	case strings.HasPrefix(strings.ToLower(compileOS), "linux"):
		t.OS = "Linux"
	default:
		t.OS = compileOS
	}
}
