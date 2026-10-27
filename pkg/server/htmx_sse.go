package server

import (
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"

	"github.com/valyala/bytebufferpool"
)

type flusher interface {
	Flush() error
}

// SSEResponse handles Server-Sent Events streaming for HTMX.
type SSEResponse struct {
	mu             *sync.Mutex
	w              io.Writer
	rc             *http.ResponseController
	acceptEncoding string

	hasSentMessage bool
}

// NewSSEWriter creates a new SSE writer and sets up the required headers.
// Returns nil if the ResponseWriter doesn't support flushing.
func NewSSEWriter(w http.ResponseWriter, r *http.Request) *SSEResponse {
	rc := http.NewResponseController(w)

	// Set SSE headers
	w.Header().Set("Access-Control-Allow-Origin", "*") // Optional: if calling from a different domain
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Content-Type", "text/event-stream")
	if r.ProtoMajor == 1 {
		w.Header().Set("Connection", "keep-alive")
	}

	if err := rc.Flush(); err != nil {
		panic(fmt.Sprintf("response writer failed to flush: %v", err))
	}

	return &SSEResponse{
		mu:             new(sync.Mutex),
		w:              w,
		rc:             rc,
		acceptEncoding: r.Header.Get("Accept-Encoding"),
		hasSentMessage: false,
	}
}

func (sse *SSEResponse) WriteHTML(html string) error {
	sse.mu.Lock()
	defer sse.mu.Unlock()

	buf := bytebufferpool.Get()
	defer bytebufferpool.Put(buf)
	if !sse.hasSentMessage {
		sse.hasSentMessage = true
	}

	for line := range strings.SplitSeq(html, "\n") {
		if err := errors.Join(
			writeJustError(buf, []byte("data: ")),
			writeJustError(buf, []byte(line)),
			writeJustError(buf, []byte{'\n'}),
		); err != nil {
			return fmt.Errorf("failed to write data: %w", err)
		}
	}
	if err := writeJustError(buf, []byte{'\n', '\n'}); err != nil {
		return fmt.Errorf("failed to write newline: %w", err)
	}

	if _, err := buf.WriteTo(sse.w); err != nil {
		return fmt.Errorf("failed to write to response writer: %w", err)
	}
	return sse.flush()
}

func (sse *SSEResponse) flush() error {
	if f, ok := sse.w.(flusher); ok {
		if err := f.Flush(); err != nil {
			return fmt.Errorf("failed to flush response writer: %w", err)
		}
	}

	if err := sse.rc.Flush(); err != nil {
		return fmt.Errorf("failed to flush data: %w", err)
	}
	return nil
}

func writeJustError(w io.Writer, b []byte) error {
	if _, err := w.Write(b); err != nil {
		return fmt.Errorf("failed to write bytes: %w", err)
	}
	return nil
}
