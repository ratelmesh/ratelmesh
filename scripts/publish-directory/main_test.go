package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestPublishDirectoryIsAtomicAndNoReplace(t *testing.T) {
	parent := t.TempDir()
	stage := filepath.Join(parent, ".stage")
	destination := filepath.Join(parent, "release")
	if err := os.Mkdir(stage, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(stage, "artifact"), []byte("complete"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := publishDirectory(stage, destination); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(stage); !os.IsNotExist(err) {
		t.Fatalf("stage still exists after publication: %v", err)
	}
	data, err := os.ReadFile(filepath.Join(destination, "artifact"))
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != "complete" {
		t.Fatalf("published artifact = %q", data)
	}

	second := filepath.Join(parent, ".second")
	if err := os.Mkdir(second, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := publishDirectory(second, destination); err == nil {
		t.Fatal("publisher replaced an existing destination")
	}
	if _, err := os.Stat(second); err != nil {
		t.Fatalf("failed publication consumed its stage: %v", err)
	}
}

func TestPublishDirectoryRejectsLinkedContent(t *testing.T) {
	parent := t.TempDir()
	stage := filepath.Join(parent, ".stage")
	destination := filepath.Join(parent, "release")
	if err := os.Mkdir(stage, 0o700); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(parent, "outside")
	if err := os.WriteFile(target, []byte("outside"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, filepath.Join(stage, "artifact")); err != nil {
		t.Fatal(err)
	}
	if err := publishDirectory(stage, destination); err == nil {
		t.Fatal("publisher accepted symbolic-link release content")
	}
	if _, err := os.Lstat(destination); !os.IsNotExist(err) {
		t.Fatalf("destination exists after rejected publication: %v", err)
	}
}
