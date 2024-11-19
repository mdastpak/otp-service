// pkg/logger/formatter.go

package logger

import (
	"bytes"
	"fmt"
	"strings"
	"time"

	"github.com/sirupsen/logrus"
)

type CustomFormatter struct {
	TimestampFormat string
	FullTimestamp   bool
}

const (
	// Colors
	red    = 31
	yellow = 33
	blue   = 36
	gray   = 37
	green  = 32
)

func getColorByLevel(level logrus.Level) int {
	switch level {
	case logrus.ErrorLevel:
		return red
	case logrus.WarnLevel:
		return yellow
	case logrus.InfoLevel:
		return blue
	case logrus.DebugLevel:
		return gray
	default:
		return blue
	}
}

func getColorByMethod(method string) int {
	switch strings.ToUpper(method) {
	case "GET":
		return blue
	case "POST":
		return green
	case "PUT":
		return yellow
	case "DELETE":
		return red
	default:
		return gray
	}
}

func colorize(color int, msg string) string {
	return fmt.Sprintf("\x1b[%dm%s\x1b[0m", color, msg)
}

func (f *CustomFormatter) Format(entry *logrus.Entry) ([]byte, error) {
	var buf *bytes.Buffer
	if entry.Buffer != nil {
		buf = entry.Buffer
	} else {
		buf = &bytes.Buffer{}
	}

	// Timestamp
	timestamp := entry.Time.Format(time.RFC3339)
	if !f.FullTimestamp {
		splitted := strings.Split(timestamp, "T")
		if len(splitted) > 0 {
			timestamp = splitted[1]
		}
	}

	// Level
	level := strings.ToUpper(entry.Level.String())
	levelColor := getColorByLevel(entry.Level)
	coloredLevel := colorize(levelColor, fmt.Sprintf("%-7s", level))

	// Message and fields
	fields := make([]string, 0)
	if method, ok := entry.Data["method"]; ok {
		methodColor := getColorByMethod(fmt.Sprint(method))
		fields = append(fields, colorize(methodColor, fmt.Sprintf("method=%-6s", method)))
	}

	if path, ok := entry.Data["path"]; ok {
		fields = append(fields, fmt.Sprintf("path=%s", path))
	}

	if status, ok := entry.Data["status"]; ok {
		statusColor := blue
		if status.(int) >= 400 {
			statusColor = red
		} else if status.(int) >= 300 {
			statusColor = yellow
		} else {
			statusColor = green
		}
		fields = append(fields, colorize(statusColor, fmt.Sprintf("status=%d", status)))
	}

	if latency, ok := entry.Data["latency"]; ok {
		fields = append(fields, fmt.Sprintf("latency=%v", latency))
	}

	if clientIP, ok := entry.Data["client_ip"]; ok {
		fields = append(fields, fmt.Sprintf("ip=%s", clientIP))
	}

	// Add remaining fields
	for k, v := range entry.Data {
		if k != "method" && k != "path" && k != "status" && k != "latency" && k != "client_ip" {
			fields = append(fields, fmt.Sprintf("%s=%v", k, v))
		}
	}

	// File and function info in debug mode
	if entry.HasCaller() {
		fields = append(fields, colorize(gray, fmt.Sprintf("file=%s:%d", entry.Caller.File, entry.Caller.Line)))
		fields = append(fields, colorize(gray, fmt.Sprintf("func=%s", entry.Caller.Function)))
	}

	// Format final output
	if len(fields) > 0 {
		fmt.Fprintf(buf, "%s %s %s | %s\n",
			colorize(gray, timestamp),
			coloredLevel,
			entry.Message,
			strings.Join(fields, " "),
		)
	} else {
		fmt.Fprintf(buf, "%s %s %s\n",
			colorize(gray, timestamp),
			coloredLevel,
			entry.Message,
		)
	}

	return buf.Bytes(), nil
}
