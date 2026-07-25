package doctorplatform

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"os/exec"
	"time"
)

const (
	commandTimeout  = 2 * time.Second
	maxCommandSize  = 256 << 10
	maxResolverSize = 64 << 10
)

var (
	errOversized = errors.New("observation exceeded size limit")
	errMalformed = errors.New("observation malformed")
)

type commandSpec struct {
	path string
	args []string
}

type commandRunner interface {
	run(context.Context, commandSpec) ([]byte, error)
}

type execRunner struct{}

func (execRunner) run(ctx context.Context, spec commandSpec) ([]byte, error) {
	ctx, cancel := context.WithTimeout(ctx, commandTimeout)
	defer cancel()

	var stdout limitedBuffer
	var stderr limitedBuffer
	cmd := exec.CommandContext(ctx, spec.path, spec.args...)
	cmd.Stdin = nil
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	err := cmd.Run()
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}
	if stdout.overflow || stderr.overflow {
		return nil, errOversized
	}
	if err != nil {
		// Never return exec.ExitError: it embeds captured stderr and could leak
		// resolver domains, addresses, or other command output.
		return nil, errors.New("native observation failed")
	}
	return bytes.Clone(stdout.buf.Bytes()), nil
}

type limitedBuffer struct {
	buf      bytes.Buffer
	overflow bool
}

func (w *limitedBuffer) Write(p []byte) (int, error) {
	original := len(p)
	remaining := maxCommandSize + 1 - w.buf.Len()
	if remaining > 0 {
		if len(p) > remaining {
			p = p[:remaining]
		}
		_, _ = w.buf.Write(p)
	}
	if w.buf.Len() > maxCommandSize {
		w.overflow = true
	}
	return original, nil
}

type boundedFileReader interface {
	read(context.Context, string, int64) ([]byte, error)
}

type osFileReader struct{}

func (osFileReader) read(ctx context.Context, path string, limit int64) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, errors.New("open resolver configuration")
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil || !info.Mode().IsRegular() {
		return nil, errors.New("resolver configuration is not a regular file")
	}
	if info.Size() > limit {
		return nil, errOversized
	}

	data, err := io.ReadAll(io.LimitReader(f, limit+1))
	if err != nil {
		return nil, errors.New("read resolver configuration")
	}
	if int64(len(data)) > limit {
		return nil, errOversized
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return data, nil
}
