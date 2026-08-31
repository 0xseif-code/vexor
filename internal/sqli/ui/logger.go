package ui

import (
	"fmt"
	"io"
	"os"
	"time"

	"github.com/fatih/color"
)

// Level identifies the severity of a log record. The logger writes records in
// the format `[HH:MM:SS] [LEVEL] message`, colour-coded on stderr.
type Level int

const (
	// INFO is routine status: connection testing, payload trials, progress.
	INFO Level = iota
	// WARNING flags recoverable anomalies, e.g. a parameter that is not dynamic.
	WARNING
	// ERROR marks a failure that does not abort the whole run.
	ERROR
	// CRITICAL marks a fatal failure.
	CRITICAL
)

func (l Level) String() string {
	switch l {
	case WARNING:
		return "WARNING"
	case ERROR:
		return "ERROR"
	case CRITICAL:
		return "CRITICAL"
	default:
		return "INFO"
	}
}

// Logger records timestamped, level-tagged messages to a Writer (stderr by
// default). Output is colour-coded via fatih/color and honours color.NoColor so
// --no-color / piped output stays plain.
type Logger struct {
	out io.Writer
}

// NewLogger returns a Logger writing to the given writer. A nil writer falls
// back to os.Stderr.
func NewLogger(w io.Writer) *Logger {
	if w == nil {
		w = os.Stderr
	}
	return &Logger{out: w}
}

// logger is the shared package-level logger used by the SQLi engine convenience
// functions below. Callers may replace it (e.g. in tests) with SetLogger.
var logger = NewLogger(os.Stderr)

// SetLogger swaps the package-level logger used by Info/Warning/Error/Critical.
func SetLogger(l *Logger) {
	if l != nil {
		logger = l
	}
}

// log renders one record with the current time and level tag.
func (lg *Logger) log(lv Level, format string, args ...any) {
	tag := fmt.Sprintf("[%s] [%s] ", stampsNow(), lv)
	msg := fmt.Sprintf(format, args...)
	switch lv {
	case WARNING:
		msg = color.New(color.FgYellow, color.Bold).Sprint(msg)
	case ERROR:
		msg = color.RedString(msg)
	case CRITICAL:
		msg = color.New(color.FgRed, color.Bold).Sprint(msg)
	default:
		// INFO: default/white.
	}
	fmt.Fprint(lg.out, tag+msg+"\n")
}

// stampsNow formats the current local wall-clock time as HH:MM:SS.
func stampsNow() string {
	return time.Now().Format("15:04:05")
}

// Log writes a record at the given level through the package logger.
func Log(lv Level, format string, args ...any) { logger.log(lv, format, args...) }

// Info logs a routine status message.
func Info(format string, args ...any) { logger.log(INFO, format, args...) }

// Infof is an alias of Info kept for call sites that use the fmt-style name.
func Infof(format string, args ...any) { logger.log(INFO, format, args...) }

// Warning logs a recoverable anomaly.
func Warning(format string, args ...any) { logger.log(WARNING, format, args...) }

// Error logs a non-fatal failure.
func Error(format string, args ...any) { logger.log(ERROR, format, args...) }

// Critical logs a fatal failure.
func Critical(format string, args ...any) { logger.log(CRITICAL, format, args...) }

// Warningf formats and logs a recoverable anomaly.
func Warningf(format string, args ...any) { logger.log(WARNING, format, args...) }

// Errorf formats and logs a non-fatal failure.
func Errorf(format string, args ...any) { logger.log(ERROR, format, args...) }

// Criticalf formats and logs a fatal failure.
func Criticalf(format string, args ...any) { logger.log(CRITICAL, format, args...) }
