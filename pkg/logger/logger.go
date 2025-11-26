package logger

import (
	"fmt"
	"log"
	"strings"
	"time"
)

// Logger handles request logging with hostname and status code
// Output format: [timestamp] hostname - statusCode
type Logger struct {
	// Could add configuration fields here if needed (log level, output writer, etc.)
}

// NewLogger creates a new Logger instance
func NewLogger() *Logger {
	return &Logger{}
}

// LogRequest logs a proxied request with hostname and HTTP status code
// Sanitizes hostname to prevent log injection attacks (SR-008)
func (l *Logger) LogRequest(hostname string, statusCode int) {
	// Sanitize hostname to prevent log injection
	sanitizedHostname := sanitizeHostname(hostname)

	// Format: [timestamp] hostname - statusCode
	timestamp := time.Now().Format(time.RFC3339)
	log.Printf("[%s] %s - %d\n", timestamp, sanitizedHostname, statusCode)
}

// LogInfo logs an informational message
func (l *Logger) LogInfo(message string) {
	log.Printf("[INFO] %s\n", message)
}

// LogError logs an error message with context
func (l *Logger) LogError(context string, err error) {
	log.Printf("[ERROR] %s: %v\n", context, err)
}

// LogCertGeneration logs certificate generation events with fingerprint (SR-004)
func (l *Logger) LogCertGeneration(hostname, fingerprint string) {
	sanitizedHostname := sanitizeHostname(hostname)
	log.Printf("[CERT] Generated certificate for %s (fingerprint: %s)\n", sanitizedHostname, fingerprint)
}

// sanitizeHostname removes potentially dangerous characters that could
// cause log injection attacks (newlines, carriage returns, control characters)
// This prevents malicious hostnames from breaking log parsing or injecting fake log entries
func sanitizeHostname(hostname string) string {
	// Remove newlines, carriage returns, and tabs
	hostname = strings.ReplaceAll(hostname, "\n", "")
	hostname = strings.ReplaceAll(hostname, "\r", "")
	hostname = strings.ReplaceAll(hostname, "\t", " ")

	// Remove other control characters (ASCII 0-31 and 127)
	var sanitized strings.Builder
	for _, ch := range hostname {
		if ch >= 32 && ch != 127 {
			sanitized.WriteRune(ch)
		}
	}

	result := sanitized.String()

	// Truncate if too long (prevent log flooding)
	const maxHostnameLen = 253 // RFC 1035 maximum DNS hostname length
	if len(result) > maxHostnameLen {
		result = result[:maxHostnameLen]
	}

	return result
}

// FormatLogEntry creates a formatted log entry string (for testing or custom output)
func FormatLogEntry(hostname string, statusCode int) string {
	sanitizedHostname := sanitizeHostname(hostname)
	timestamp := time.Now().Format(time.RFC3339)
	return fmt.Sprintf("[%s] %s - %d", timestamp, sanitizedHostname, statusCode)
}
