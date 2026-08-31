package ui

import (
	"fmt"
	"io"
	"os"

	"github.com/0xseif-code/vexor/internal/sqli/fingerprint"
)

// InjectionSummary describes one confirmed injection point for display by the
// summary box.
type InjectionSummary struct {
	// Parameter is the name of the affected parameter (e.g. "cat").
	Parameter string
	// Method is the request method / point type (e.g. "GET", "POST").
	Method string
	// Type is the detection technique family (e.g. "error-based").
	Type string
	// Title is the full payload title (e.g. "MySQL >= 5.0 (inline) error-based
	// - Table name clause (FLOOR)").
	Title string
	// Payload is the injection fragment (e.g. `cat=1 AND (SELECT 3337 FROM ...)`).
	Payload string
}

// PrintInjectionPointBox writes the post-detection summary to w (stderr by
// default):
//
//	Vexor identified the following injection point(s) with a total of N HTTP(s)
//	requests:
//
//	Parameter: cat (GET)
//	Type: error-based
//	Title: MySQL >= 5.0 (inline) error-based - Table name clause (FLOOR)
//	Payload: cat=1 AND (SELECT 3337 FROM ...)
//
// followed by a blank line. A nil writer defaults to os.Stderr.
func PrintInjectionPointBox(w io.Writer, requests int, points []InjectionSummary) {
	if w == nil {
		w = os.Stderr
	}
	fmt.Fprintf(w, "Vexor identified the following injection point(s) with a total of %d HTTP(s) requests:\n", requests)
	for _, p := range points {
		fmt.Fprintln(w)
		method := p.Method
		if method == "" {
			method = "GET"
		}
		typeLabel := p.Type
		if typeLabel == "" {
			typeLabel = "error-based"
		}
		fmt.Fprintf(w, "Parameter: %s (%s)\n", p.Parameter, method)
		fmt.Fprintf(w, "Type: %s\n", typeLabel)
		if p.Title != "" {
			fmt.Fprintf(w, "Title: %s\n", p.Title)
		}
		if p.Payload != "" {
			fmt.Fprintf(w, "Payload: %s\n", p.Payload)
		}
	}
	fmt.Fprintln(w)
}

// PrintTechFingerprint writes the technology fingerprint banner to w (stderr by
// default):
//
//	[HH:MM:SS] [INFO] the back-end DBMS is MySQL
//	web server operating system: Linux Fedora 13
//	web application technology: PHP 5.3.3, Apache 2.2.15
//	back-end DBMS: MySQL >= 5.0
//
// A nil writer defaults to os.Stderr. Fields that are empty are reported as
// "unknown" so the operator can tell identification actually ran.
func PrintTechFingerprint(w io.Writer, t fingerprint.TechFingerprint) {
	if w == nil {
		w = os.Stderr
	}
	dbmsLabel := t.DBMSShort
	if dbmsLabel == "" {
		dbmsLabel = "unknown"
	}
	Log(INFO, "the back-end DBMS is %s", dbmsLabel)
	if t.OS == "" {
		fmt.Fprintln(w, "web server operating system: unknown")
	} else {
		fmt.Fprintf(w, "web server operating system: %s\n", t.OS)
	}
	app := t.AppTech
	if app == "" {
		app = "unknown"
	}
	if t.WebServer == "" {
		fmt.Fprintf(w, "web application technology: %s\n", app)
	} else if app == "unknown" {
		fmt.Fprintf(w, "web application technology: %s\n", t.WebServer)
	} else {
		fmt.Fprintf(w, "web application technology: %s, %s\n", app, t.WebServer)
	}
	fmt.Fprintf(w, "back-end DBMS: %s\n", dbmsLabel)
}
