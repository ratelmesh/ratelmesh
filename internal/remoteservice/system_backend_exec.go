package remoteservice

import (
	"context"
	"io"
	"os/exec"
	"runtime"
)

type limitedWriter struct {
	buffer    []byte
	limit     int
	truncated bool
}

func (w *limitedWriter) Write(data []byte) (int, error) {
	original := len(data)
	remaining := w.limit - len(w.buffer)
	if remaining > 0 {
		if len(data) > remaining {
			w.buffer = append(w.buffer, data[:remaining]...)
			w.truncated = true
		} else {
			w.buffer = append(w.buffer, data...)
		}
	} else if len(data) > 0 {
		w.truncated = true
	}
	return original, nil
}

type execCommandRunner struct{}

func (execCommandRunner) Run(ctx context.Context, spec commandSpec, limit int) (commandResult, error) {
	command := exec.CommandContext(ctx, spec.executable, spec.arguments...)
	command.Env = fixedCommandEnvironment(runtime.GOOS)
	command.Dir = fixedCommandDirectory(runtime.GOOS)
	command.Stdin = nil
	stdout := &limitedWriter{limit: limit}
	stderr := &limitedWriter{limit: limit}
	command.Stdout = stdout
	command.Stderr = stderr
	err := command.Run()
	return commandResult{
		stdout:    string(stdout.buffer),
		stderr:    string(stderr.buffer),
		truncated: stdout.truncated || stderr.truncated,
	}, err
}

func fixedCommandEnvironment(goos string) []string {
	if goos == "windows" {
		return []string{
			`PATH=C:\Windows\System32`,
			`SystemRoot=C:\Windows`,
			`WINDIR=C:\Windows`,
		}
	}
	return []string{
		"PATH=/usr/bin:/bin:/usr/sbin:/sbin",
		"LANG=C",
		"LC_ALL=C",
	}
}

func fixedCommandDirectory(goos string) string {
	if goos == "windows" {
		return `C:\Windows\System32`
	}
	return "/"
}

var _ io.Writer = (*limitedWriter)(nil)
