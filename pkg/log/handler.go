package log

import (
	"context"
	"log/slog"
)

// delegateHandler forwards to slog.Default().Handler() at log time so package-
// level loggers created before Init() still honor post-Init level and format.
type delegateHandler struct {
	attrs []slog.Attr
}

func (h *delegateHandler) Enabled(ctx context.Context, level slog.Level) bool {
	return slog.Default().Handler().Enabled(ctx, level)
}

func (h *delegateHandler) Handle(ctx context.Context, r slog.Record) error {
	if len(h.attrs) > 0 {
		r.AddAttrs(h.attrs...)
	}
	return slog.Default().Handler().Handle(ctx, r)
}

func (h *delegateHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	combined := append(append([]slog.Attr{}, h.attrs...), attrs...)
	return &delegateHandler{attrs: combined}
}

func (h *delegateHandler) WithGroup(name string) slog.Handler {
	return &delegateHandler{attrs: h.attrs}
}
