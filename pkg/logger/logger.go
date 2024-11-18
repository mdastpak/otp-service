// pkg/logger/logger.go

package logger

import (
	"io"
	"os"
	"time"

	"github.com/sirupsen/logrus"
)

var log = logrus.New()

// Config holds logger configuration
type Config struct {
	Level        string
	ReportCaller bool
	JSONFormat   bool
	Output       io.Writer
}

// InitLogger initializes the logger with given config
func InitLogger(cfg *Config) {
	// Set log level
	level, err := logrus.ParseLevel(cfg.Level)
	if err != nil {
		level = logrus.InfoLevel
	}
	log.SetLevel(level)

	// Set output format
	if cfg.JSONFormat {
		log.SetFormatter(&logrus.JSONFormatter{
			TimestampFormat: time.RFC3339,
		})
	} else {
		log.SetFormatter(&logrus.TextFormatter{
			TimestampFormat: time.RFC3339,
			FullTimestamp:   true,
		})
	}

	// Set output
	if cfg.Output != nil {
		log.SetOutput(cfg.Output)
	} else {
		log.SetOutput(os.Stdout)
	}

	// Set caller reporting
	log.SetReportCaller(cfg.ReportCaller)
}

// GetLogger returns the configured logger instance
func GetLogger() *logrus.Logger {
	return log
}

// Error logs error level message
func Error(args ...interface{}) {
	log.Error(args...)
}

// Info logs info level message
func Info(args ...interface{}) {
	log.Info(args...)
}

// Debug logs debug level message
func Debug(args ...interface{}) {
	log.Debug(args...)
}

// Warn logs warn level message
func Warn(args ...interface{}) {
	log.Warn(args...)
}
