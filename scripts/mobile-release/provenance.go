// Command provenance writes a deterministic, fail-closed provenance record for
// a locally built mobile preview artifact.
package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

type provenanceRecord struct {
	Schema          int    `json:"schema"`
	Platform        string `json:"platform"`
	Classification  string `json:"classification"`
	Artifact        string `json:"artifact"`
	Version         string `json:"version"`
	Build           string `json:"build"`
	SourceCommit    string `json:"sourceCommit"`
	SourceDateEpoch int64  `json:"sourceDateEpoch"`
	SHA256          string `json:"sha256"`
	Size            int64  `json:"size"`
	Signing         string `json:"signing"`
	SignerSHA256    string `json:"signerSHA256,omitempty"`
	Toolchain       string `json:"toolchain"`
}

var (
	versionPattern = regexp.MustCompile(`^(0|[1-9][0-9]{0,5})\.(0|[1-9][0-9]{0,5})\.(0|[1-9][0-9]{0,5})$`)
	buildPattern   = regexp.MustCompile(`^[1-9][0-9]*$`)
	commitPattern  = regexp.MustCompile(`^[0-9a-f]{40}([0-9a-f]{24})?$`)
	digestPattern  = regexp.MustCompile(`^[0-9a-f]{64}$`)
)

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "mobile provenance:", err)
		os.Exit(1)
	}
}

func run(args []string) error {
	flags := flag.NewFlagSet("provenance", flag.ContinueOnError)
	artifact := flags.String("artifact", "", "artifact to hash")
	platform := flags.String("platform", "", "android or ios")
	classification := flags.String("classification", "", "release classification")
	version := flags.String("version", "", "semantic version")
	build := flags.String("build", "", "positive build number")
	sourceCommit := flags.String("source-commit", "", "full Git commit")
	sourceEpoch := flags.Int64("source-date-epoch", 0, "source commit Unix timestamp")
	signing := flags.String("signing", "", "debug or unsigned")
	signerDigest := flags.String("signer-sha256", "", "lowercase signing certificate digest")
	toolchain := flags.String("toolchain", "", "concise toolchain identity")
	output := flags.String("output", "", "new provenance JSON path")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return errors.New("unexpected positional arguments")
	}
	if *artifact == "" || *classification == "" || *version == "" || *build == "" ||
		*sourceCommit == "" || *toolchain == "" || *output == "" {
		return errors.New("artifact, classification, version, build, source commit, toolchain, and output are required")
	}
	if !versionPattern.MatchString(*version) || !buildPattern.MatchString(*build) {
		return errors.New("invalid version or build")
	}
	if !commitPattern.MatchString(*sourceCommit) || *sourceEpoch < 315532800 {
		return errors.New("invalid source identity")
	}
	switch *platform {
	case "android":
		if *classification != "debug-signed-test" || *signing != "debug" ||
			!digestPattern.MatchString(*signerDigest) {
			return errors.New("android preview must be debug classified with a certificate digest")
		}
	case "ios":
		if *classification != "unsigned-developer-preview" || *signing != "unsigned" ||
			*signerDigest != "" {
			return errors.New("iOS preview must be explicitly unsigned without a signer digest")
		}
	default:
		return errors.New("unsupported platform")
	}
	if strings.ContainsAny(*toolchain, "\r\n") || strings.TrimSpace(*toolchain) != *toolchain {
		return errors.New("toolchain must be one non-empty trimmed line")
	}
	digest, size, err := hashArtifact(*artifact)
	if err != nil {
		return err
	}
	record := provenanceRecord{
		Schema: 1, Platform: *platform, Classification: *classification,
		Artifact: filepath.Base(*artifact), Version: *version, Build: *build,
		SourceCommit: *sourceCommit, SourceDateEpoch: *sourceEpoch,
		SHA256: digest, Size: size, Signing: *signing,
		SignerSHA256: *signerDigest, Toolchain: *toolchain,
	}
	data, err := json.MarshalIndent(record, "", "  ")
	if err != nil {
		return err
	}
	return writeExclusive(*output, append(data, '\n'))
}

func hashArtifact(path string) (string, int64, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return "", 0, err
	}
	if !info.Mode().IsRegular() || info.Size() <= 0 {
		return "", 0, errors.New("artifact must be a non-empty regular file")
	}
	file, err := os.Open(path)
	if err != nil {
		return "", 0, err
	}
	defer file.Close()
	hash := sha256.New()
	size, err := io.Copy(hash, file)
	if err != nil {
		return "", 0, err
	}
	return hex.EncodeToString(hash.Sum(nil)), size, nil
}

func writeExclusive(path string, data []byte) error {
	if filepath.Base(path) == "." || filepath.Base(path) == string(filepath.Separator) {
		return errors.New("invalid output path")
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o644)
	if err != nil {
		return err
	}
	keep := false
	defer func() {
		if !keep {
			_ = os.Remove(path)
		}
	}()
	if _, err := file.Write(data); err != nil {
		_ = file.Close()
		return err
	}
	if err := file.Sync(); err != nil {
		_ = file.Close()
		return err
	}
	if err := file.Close(); err != nil {
		return err
	}
	dir, err := os.Open(filepath.Dir(path))
	if err != nil {
		return err
	}
	if err := dir.Sync(); err != nil {
		_ = dir.Close()
		return err
	}
	if err := dir.Close(); err != nil {
		return err
	}
	keep = true
	return nil
}
