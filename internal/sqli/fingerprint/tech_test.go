package fingerprint

import (
	"testing"

	"github.com/0xseif-code/vexor/internal/httpclient"
)

func TestFromResponseApacheFedora(t *testing.T) {
	var tf TechFingerprint
	tf.FromResponse(&httpclient.Response{
		Headers: map[string]string{
			"Server":        "Apache/2.2.15 (Fedora)",
			"X-Powered-By":  "PHP/5.3.3",
		},
	})
	if tf.WebServer != "Apache/2.2.15" {
		t.Errorf("WebServer = %q, want %q", tf.WebServer, "Apache/2.2.15")
	}
	if tf.OS != "Linux Fedora" {
		t.Errorf("OS = %q, want %q", tf.OS, "Linux Fedora")
	}
	if tf.AppTech != "PHP/5.3.3" {
		t.Errorf("AppTech = %q, want %q", tf.AppTech, "PHP/5.3.3")
	}
}

func TestFromResponseNginxUbuntu(t *testing.T) {
	var tf TechFingerprint
	tf.FromResponse(&httpclient.Response{
		Headers: map[string]string{"Server": "nginx/1.18.0 (Ubuntu)"},
	})
	if tf.WebServer != "nginx/1.18.0" {
		t.Errorf("WebServer = %q, want %q", tf.WebServer, "nginx/1.18.0")
	}
	if tf.OS != "Linux Ubuntu" {
		t.Errorf("OS = %q, want %q", tf.OS, "Linux Ubuntu")
	}
}

func TestFromResponseEmpty(t *testing.T) {
	var tf TechFingerprint
	tf.FromResponse(nil)
	if tf.WebServer != "" || tf.OS != "" || tf.AppTech != "" {
		t.Fatal("nil response should leave fields empty")
	}
}

func TestFromDBMSVersionMySQL(t *testing.T) {
	var tf TechFingerprint
	tf.FromDBMSVersion("MySQL 5.1.41-community")
	if tf.DBMSFull != "MySQL 5.1.41" {
		t.Errorf("DBMSFull = %q, want %q", tf.DBMSFull, "MySQL 5.1.41")
	}
	if tf.DBMSShort != "MySQL >= 5.1" {
		t.Errorf("DBMSShort = %q, want %q", tf.DBMSShort, "MySQL >= 5.1")
	}
}

func TestFromDBMSVersionBare(t *testing.T) {
	var tf TechFingerprint
	tf.FromDBMSVersion("5.5.62")
	if tf.DBMSShort != "MySQL >= 5.5" {
		t.Errorf("DBMSShort = %q, want %q", tf.DBMSShort, "MySQL >= 5.5")
	}
	if tf.DBMSFull != "MySQL 5.5.62" {
		t.Errorf("DBMSFull = %q, want %q", tf.DBMSFull, "MySQL 5.5.62")
	}
}

func TestFromDBMSCompileOS(t *testing.T) {
	var tf TechFingerprint
	tf.FromDBMSCompileOS("Win64")
	if tf.OS != "Windows" {
		t.Errorf("OS = %q, want Windows", tf.OS)
	}
	tf = TechFingerprint{}
	tf.FromDBMSCompileOS("Linux")
	if tf.OS != "Linux" {
		t.Errorf("OS = %q, want Linux", tf.OS)
	}
}
