// Package log configures structured logging for k8s-sniffer.
//
// See docs/LOGGING.md for conventions (info = what happened, debug = how).
package log

import (
	"fmt"
	"io"
	"log/slog"
	"os"
	"strings"
)

const (
	// EnvLevel is the environment variable for default log verbosity.
	EnvLevel = "K8S_SNIFFER_LOG_LEVEL"
)

// Level is the supported log verbosity. Only info and debug are used.
type Level string

const (
	LevelInfo  Level = "info"
	LevelDebug Level = "debug"
)

// Config configures the process-wide default logger.
type Config struct {
	Level  Level
	Writer io.Writer
	JSON   bool
}

// ParseLevel parses s as info or debug. Empty string means info.
func ParseLevel(s string) (Level, error) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "", "info":
		return LevelInfo, nil
	case "debug":
		return LevelDebug, nil
	default:
		return "", fmt.Errorf("invalid log level %q (want info or debug)", s)
	}
}

// Init replaces slog.Default with a logger configured from cfg. Writer defaults
// to os.Stderr. Safe to call more than once (e.g. flag overrides env).
func Init(cfg Config) {
	if cfg.Writer == nil {
		cfg.Writer = os.Stderr
	}
	if cfg.Level == "" {
		cfg.Level = LevelInfo
	}
	opts := &slog.HandlerOptions{Level: toSlogLevel(cfg.Level)}
	var handler slog.Handler
	if cfg.JSON {
		handler = slog.NewJSONHandler(cfg.Writer, opts)
	} else {
		handler = slog.NewTextHandler(cfg.Writer, opts)
	}
	slog.SetDefault(slog.New(handler))
}

// InitFromEnv configures logging from K8S_SNIFFER_LOG_LEVEL (default info).
func InitFromEnv() {
	level, err := ParseLevel(os.Getenv(EnvLevel))
	if err != nil {
		level = LevelInfo
	}
	Init(Config{Level: level})
}

// ResolveLevel returns flag when non-empty, else env, else info.
func ResolveLevel(flag, env string) (Level, error) {
	if strings.TrimSpace(flag) != "" {
		return ParseLevel(flag)
	}
	return ParseLevel(env)
}

// Default returns the process-wide logger (slog.Default after Init).
func Default() *slog.Logger {
	return slog.Default()
}

// WithComponent returns a child logger tagged for grep-friendly filtering.
func WithComponent(component string) *slog.Logger {
	return Default().With("component", component)
}

func toSlogLevel(level Level) slog.Level {
	if level == LevelDebug {
		return slog.LevelDebug
	}
	return slog.LevelInfo
}
