package relay

import (
	"bytes"
	"testing"
)

type shortWriter struct {
	bytes.Buffer
	limit int
}

func (w *shortWriter) Write(p []byte) (int, error) {
	if len(p) > w.limit {
		p = p[:w.limit]
	}
	return w.Buffer.Write(p)
}

func TestWriteFrameCompletesShortWrites(t *testing.T) {
	var dst shortWriter
	dst.limit = 2
	payload := []byte("long-lived-video-frame")
	if err := writeFrame(&dst, FrameForward, payload); err != nil {
		t.Fatal(err)
	}
	frameType, got, err := readFrame(bytes.NewReader(dst.Bytes()))
	if err != nil {
		t.Fatalf("read written frame: %v", err)
	}
	if frameType != FrameForward || !bytes.Equal(got, payload) {
		t.Fatalf("frame = type %v payload %q", frameType, got)
	}
}
