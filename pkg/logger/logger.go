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
	Mode         string
	ReportCaller bool
	JSONFormat   bool
	Output       io.Writer
}

// InitLogger initializes the logger based on application mode
func InitLogger(cfg *Config) {
	formatter := &CustomFormatter{
		TimestampFormat: time.RFC3339,
		FullTimestamp:   true,
	}

	switch cfg.Mode {
	case "debug", "test":
		log.SetLevel(logrus.DebugLevel)
		log.SetFormatter(formatter)
		log.SetReportCaller(true)
	case "release":
		log.SetLevel(logrus.InfoLevel)
		if cfg.JSONFormat {
			log.SetFormatter(&logrus.JSONFormatter{
				TimestampFormat: time.RFC3339,
			})
		} else {
			log.SetFormatter(formatter)
		}
		log.SetReportCaller(false)
	}

	if cfg.Output != nil {
		log.SetOutput(cfg.Output)
	} else {
		log.SetOutput(os.Stdout)
	}
}

func GetLogger() *logrus.Logger {
	return log
}

// Standard logging methods
func Error(args ...interface{}) {
	log.Error(args...)
}

func Info(args ...interface{}) {
	log.Info(args...)
}

func Debug(args ...interface{}) {
	log.Debug(args...)
}

func Warn(args ...interface{}) {
	log.Warn(args...)
}
