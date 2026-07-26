package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestAndroidProvenanceIsDeterministicAndExclusive(t *testing.T) {
	dir := t.TempDir()
	artifact := filepath.Join(dir, "RatelMesh-Android-1.2.3-debug.apk")
	payload := []byte("signed apk fixture")
	if err := os.WriteFile(artifact, payload, 0o644); err != nil {
		t.Fatal(err)
	}
	output := filepath.Join(dir, "artifact.provenance.json")
	args := []string{
		"-artifact", artifact,
		"-platform", "android",
		"-classification", "debug-signed-test",
		"-version", "1.2.3",
		"-build", "123",
		"-source-commit", "0123456789abcdef0123456789abcdef01234567",
		"-source-date-epoch", "1785031200",
		"-signing", "debug",
		"-signer-sha256", "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789",
		"-toolchain", "go=go1.26.0; gradle=8.11; android-build-tools=35.0.0",
		"-output", output,
	}
	if err := run(args); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(output)
	if err != nil {
		t.Fatal(err)
	}
	var record provenanceRecord
	if err := json.Unmarshal(data, &record); err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(payload)
	if record.SHA256 != hex.EncodeToString(digest[:]) || record.Size != int64(len(payload)) {
		t.Fatalf("artifact identity = %s/%d", record.SHA256, record.Size)
	}
	if record.Signing != "debug" || record.SignerSHA256 == "" ||
		record.Classification != "debug-signed-test" {
		t.Fatalf("unsafe Android classification: %+v", record)
	}
	if err := run(args); err == nil {
		t.Fatal("provenance overwrote an existing record")
	}
}

func TestIOSProvenanceMustRemainExplicitlyUnsigned(t *testing.T) {
	dir := t.TempDir()
	artifact := filepath.Join(dir, "RatelMesh-iOS-1.2.3-unsigned.zip")
	if err := os.WriteFile(artifact, []byte("unsigned app fixture"), 0o644); err != nil {
		t.Fatal(err)
	}
	base := []string{
		"-artifact", artifact,
		"-platform", "ios",
		"-classification", "unsigned-developer-preview",
		"-version", "1.2.3",
		"-build", "123",
		"-source-commit", "0123456789abcdef0123456789abcdef01234567",
		"-source-date-epoch", "1785031200",
		"-signing", "unsigned",
		"-toolchain", "xcode=26.4; swift=6.2",
	}
	if err := run(append(base, "-output", filepath.Join(dir, "valid.json"))); err != nil {
		t.Fatal(err)
	}
	bad := append([]string{}, base...)
	for index := range bad {
		if bad[index] == "unsigned" {
			bad[index] = "development"
		}
	}
	if err := run(append(bad, "-output", filepath.Join(dir, "bad.json"))); err == nil {
		t.Fatal("signed-looking iOS provenance was accepted as an unsigned preview")
	}
}

func TestProvenanceRejectsSymlinkArtifactAndOutput(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "target")
	if err := os.WriteFile(target, []byte("payload"), 0o644); err != nil {
		t.Fatal(err)
	}
	artifact := filepath.Join(dir, "artifact.apk")
	if err := os.Symlink(target, artifact); err != nil {
		t.Fatal(err)
	}
	args := []string{
		"-artifact", artifact,
		"-platform", "android",
		"-classification", "debug-signed-test",
		"-version", "1.2.3",
		"-build", "123",
		"-source-commit", "0123456789abcdef0123456789abcdef01234567",
		"-source-date-epoch", "1785031200",
		"-signing", "debug",
		"-signer-sha256", "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789",
		"-toolchain", "fixture",
		"-output", filepath.Join(dir, "record.json"),
	}
	if err := run(args); err == nil {
		t.Fatal("symlink artifact was accepted")
	}

	if err := os.Remove(artifact); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(artifact, []byte("payload"), 0o644); err != nil {
		t.Fatal(err)
	}
	output := filepath.Join(dir, "record.json")
	if err := os.Symlink(target, output); err != nil {
		t.Fatal(err)
	}
	args[len(args)-1] = output
	if err := run(args); err == nil {
		t.Fatal("symlink output was followed")
	}
}
