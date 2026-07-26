package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestValidVersion(t *testing.T) {
	for _, version := range []string{"0.1.26", "13.0", "999999.0.1"} {
		if !validVersion(version, 2, 3) {
			t.Fatalf("expected valid version %q", version)
		}
	}
	for _, version := range []string{"", "1", "01.2.3", "1.2.3.4", "1.2.beta", "1000000.1.1"} {
		if validVersion(version, 2, 3) {
			t.Fatalf("expected invalid version %q", version)
		}
	}
}

func TestValidPackageURL(t *testing.T) {
	const version = "0.1.26"
	valid := "https://download.ratelmesh.com/download/RatelMesh-macOS-0.1.26-universal.pkg"
	if !validPackageURL(valid, version) {
		t.Fatal("expected official package URL to be valid")
	}
	for _, candidate := range []string{
		"http://download.ratelmesh.com/download/RatelMesh-macOS-0.1.26-universal.pkg",
		"https://example.com/download/RatelMesh-macOS-0.1.26-universal.pkg",
		"https://download.ratelmesh.com/download/RatelMesh-macOS-0.1.25-universal.pkg",
		"https://download.ratelmesh.com/download/RatelMesh-macOS-0.1.26-universal.pkg?mirror=1",
		"https://download.ratelmesh.com:443/download/RatelMesh-macOS-0.1.26-universal.pkg",
	} {
		if validPackageURL(candidate, version) {
			t.Fatalf("expected unsafe package URL to be invalid: %q", candidate)
		}
	}
}

func TestValidPublishedAtRejectsFractionalSeconds(t *testing.T) {
	for _, value := range []string{"2026-07-13T18:15:00Z", "2026-07-13T11:15:00-07:00"} {
		if err := validPublishedAt(value); err != nil {
			t.Fatalf("validPublishedAt(%q): %v", value, err)
		}
	}
	for _, value := range []string{"2026-07-13T18:15:00.123Z", "2026-07-13T18:15:00.000Z", "not-a-date"} {
		if err := validPublishedAt(value); err == nil {
			t.Fatalf("validPublishedAt(%q) unexpectedly succeeded", value)
		}
	}
}

func TestKeygenRejectsOrphanCompanionWithoutCreatingPrimary(t *testing.T) {
	keyPath := filepath.Join(t.TempDir(), "release.key")
	if err := os.WriteFile(keyPath+".mldsa65", []byte("orphan\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := keygen([]string{"-key", keyPath}); err == nil {
		t.Fatal("keygen accepted an orphaned ML-DSA companion")
	}
	if _, err := os.Lstat(keyPath); !os.IsNotExist(err) {
		t.Fatalf("keygen left a primary key after rejecting companion: %v", err)
	}
}

func TestKeygenCreatesPrivatePairAndRefusesOverwrite(t *testing.T) {
	keyPath := filepath.Join(t.TempDir(), "release.key")
	if err := keygen([]string{"-key", keyPath}); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{keyPath, keyPath + ".mldsa65"} {
		info, err := os.Lstat(path)
		if err != nil {
			t.Fatal(err)
		}
		if !info.Mode().IsRegular() || info.Mode().Perm() != 0o600 {
			t.Fatalf("%s mode = %v, want regular 0600", path, info.Mode())
		}
	}
	if err := keygen([]string{"-key", keyPath}); err == nil {
		t.Fatal("keygen overwrote an existing release key pair")
	}
}

func TestPrivateKeyReadRejectsSymlinkAndSwap(t *testing.T) {
	dir := t.TempDir()
	original := filepath.Join(dir, "release.key")
	replacement := filepath.Join(dir, "replacement.key")
	if err := os.WriteFile(original, []byte("original"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(replacement, []byte("replacement"), 0o600); err != nil {
		t.Fatal(err)
	}

	link := filepath.Join(dir, "release-link.key")
	if err := os.Symlink(original, link); err != nil {
		t.Fatal(err)
	}
	if _, err := loadPrivateFile(link, "test key", os.Open); err == nil {
		t.Fatal("private key reader followed an initial symbolic link")
	}

	saved := filepath.Join(dir, "saved.key")
	swapOpen := func(path string) (*os.File, error) {
		if err := os.Rename(path, saved); err != nil {
			return nil, err
		}
		if err := os.Symlink(replacement, path); err != nil {
			return nil, err
		}
		return os.Open(path)
	}
	if _, err := loadPrivateFile(original, "test key", swapOpen); err == nil ||
		!strings.Contains(err.Error(), "changed while it was being opened") {
		t.Fatalf("private key swap was not rejected: %v", err)
	}
}

func TestExclusiveWritePublishesCompleteFileWithoutStageResidue(t *testing.T) {
	dir := t.TempDir()
	output := filepath.Join(dir, "latest.json")
	if err := writeExclusiveFile(output, []byte("complete\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(output)
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != "complete\n" {
		t.Fatalf("published content = %q", data)
	}
	stages, err := filepath.Glob(filepath.Join(dir, ".latest.json.stage-*"))
	if err != nil {
		t.Fatal(err)
	}
	if len(stages) != 0 {
		t.Fatalf("staged files remain after publication: %v", stages)
	}
	if err := writeExclusiveFile(output, []byte("replacement\n"), 0o644); err == nil {
		t.Fatal("exclusive writer replaced an existing output")
	}
}

func TestSignRefusesExistingOrSymlinkManifest(t *testing.T) {
	dir := t.TempDir()
	keyPath := filepath.Join(dir, "release.key")
	if err := keygen([]string{"-key", keyPath}); err != nil {
		t.Fatal(err)
	}
	pkg := filepath.Join(dir, "RatelMesh-macOS-1.2.3-universal.pkg")
	if err := os.WriteFile(pkg, []byte("package"), 0o644); err != nil {
		t.Fatal(err)
	}
	output := filepath.Join(dir, "latest.json")
	const sentinel = "do not replace\n"
	if err := os.WriteFile(output, []byte(sentinel), 0o644); err != nil {
		t.Fatal(err)
	}
	args := []string{
		"-key", keyPath,
		"-package", pkg,
		"-version", "1.2.3",
		"-url", "https://download.ratelmesh.com/download/RatelMesh-macOS-1.2.3-universal.pkg",
		"-published-at", "2026-07-26T03:00:00Z",
		"-output", output,
	}
	if err := sign(args); err == nil {
		t.Fatal("sign overwrote an existing manifest")
	}
	data, err := os.ReadFile(output)
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != sentinel {
		t.Fatalf("existing manifest changed: %q", data)
	}

	if err := os.Remove(output); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(dir, "target")
	if err := os.WriteFile(target, []byte(sentinel), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, output); err != nil {
		t.Fatal(err)
	}
	if err := sign(args); err == nil {
		t.Fatal("sign followed a manifest symlink")
	}
	data, err = os.ReadFile(target)
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != sentinel {
		t.Fatalf("symlink target changed: %q", data)
	}
}

func TestSignRejectsSymlinkPackage(t *testing.T) {
	dir := t.TempDir()
	keyPath := filepath.Join(dir, "release.key")
	if err := keygen([]string{"-key", keyPath}); err != nil {
		t.Fatal(err)
	}
	realPackage := filepath.Join(dir, "real.pkg")
	if err := os.WriteFile(realPackage, []byte("package"), 0o644); err != nil {
		t.Fatal(err)
	}
	linkedPackage := filepath.Join(dir, "RatelMesh-macOS-1.2.3-universal.pkg")
	if err := os.Symlink(realPackage, linkedPackage); err != nil {
		t.Fatal(err)
	}
	err := sign([]string{
		"-key", keyPath,
		"-package", linkedPackage,
		"-version", "1.2.3",
		"-url", "https://download.ratelmesh.com/download/RatelMesh-macOS-1.2.3-universal.pkg",
		"-published-at", "2026-07-26T03:00:00Z",
		"-output", filepath.Join(dir, "latest.json"),
	})
	if err == nil {
		t.Fatal("sign accepted a symbolic-link package")
	}
}
