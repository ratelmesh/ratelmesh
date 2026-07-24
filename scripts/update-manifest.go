// Command update-manifest creates an offline Ed25519 release key or signs a
// macOS update manifest. The private seed stays outside the repository.
package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/cloudflare/circl/sign/mldsa/mldsa65"
)

type manifest struct {
	Schema               int    `json:"schema"`
	Platform             string `json:"platform"`
	Version              string `json:"version"`
	MinimumSystemVersion string `json:"minimumSystemVersion"`
	URL                  string `json:"url"`
	SHA256               string `json:"sha256"`
	Size                 int64  `json:"size"`
	PublishedAt          string `json:"publishedAt"`
	Signature            string `json:"signature"`
	PQSignature          string `json:"pqSignature,omitempty"`
}

func main() {
	if len(os.Args) < 2 {
		fatal(errors.New("usage: update-manifest <keygen|public|public-pq|sign> [flags]"))
	}
	var err error
	switch os.Args[1] {
	case "keygen":
		err = keygen(os.Args[2:])
	case "public":
		err = public(os.Args[2:])
	case "public-pq":
		err = publicPQ(os.Args[2:])
	case "sign":
		err = sign(os.Args[2:])
	default:
		err = fmt.Errorf("unknown command %q", os.Args[1])
	}
	if err != nil {
		fatal(err)
	}
}

func publicPQ(args []string) error {
	flags := flag.NewFlagSet("public-pq", flag.ContinueOnError)
	keyPath := flags.String("key", "", "path to the base64 Ed25519 seed")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if *keyPath == "" {
		return errors.New("-key is required")
	}
	key, err := loadMLDSAPrivateKey(*keyPath + ".mldsa65")
	if err != nil {
		return err
	}
	fmt.Println(base64.StdEncoding.EncodeToString(key.Public().(*mldsa65.PublicKey).Bytes()))
	return nil
}

func public(args []string) error {
	flags := flag.NewFlagSet("public", flag.ContinueOnError)
	keyPath := flags.String("key", "", "path to the base64 Ed25519 seed")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if *keyPath == "" {
		return errors.New("-key is required")
	}
	privateKey, err := loadPrivateKey(*keyPath)
	if err != nil {
		return err
	}
	fmt.Println(base64.StdEncoding.EncodeToString(privateKey.Public().(ed25519.PublicKey)))
	return nil
}

func keygen(args []string) error {
	flags := flag.NewFlagSet("keygen", flag.ContinueOnError)
	keyPath := flags.String("key", "", "path for the base64 Ed25519 seed")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if *keyPath == "" {
		return errors.New("-key is required")
	}
	if _, err := os.Lstat(*keyPath); err == nil {
		return fmt.Errorf("release key already exists: %s", *keyPath)
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(*keyPath), 0o700); err != nil {
		return err
	}
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return err
	}
	seed := base64.StdEncoding.EncodeToString(privateKey.Seed()) + "\n"
	file, err := os.OpenFile(*keyPath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	if _, err := file.WriteString(seed); err != nil {
		file.Close()
		return err
	}
	if err := file.Close(); err != nil {
		return err
	}
	if err := os.Chmod(*keyPath, 0o600); err != nil {
		return err
	}
	_, pqPrivate, err := mldsa65.GenerateKey(rand.Reader)
	if err != nil {
		return err
	}
	if err := writeMLDSASeed(*keyPath+".mldsa65", pqPrivate); err != nil {
		return err
	}
	fmt.Println(base64.StdEncoding.EncodeToString(publicKey))
	return nil
}

func sign(args []string) error {
	flags := flag.NewFlagSet("sign", flag.ContinueOnError)
	keyPath := flags.String("key", "", "path to the base64 Ed25519 seed")
	packagePath := flags.String("package", "", "macOS package to hash")
	version := flags.String("version", "", "release version")
	packageURL := flags.String("url", "", "public HTTPS package URL")
	minimum := flags.String("minimum-system", "13.0", "minimum macOS version")
	publishedAt := flags.String("published-at", "", "RFC3339 publication time")
	output := flags.String("output", "", "manifest output path")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if *keyPath == "" || *packagePath == "" || *version == "" || *packageURL == "" || *output == "" {
		return errors.New("-key, -package, -version, -url, and -output are required")
	}
	if !validVersion(*version, 3) || !validVersion(*minimum, 2, 3) {
		return errors.New("invalid version")
	}
	if !validPackageURL(*packageURL, *version) {
		return errors.New("invalid package URL")
	}
	when := *publishedAt
	if when == "" {
		when = time.Now().UTC().Format(time.RFC3339)
	}
	if err := validPublishedAt(when); err != nil {
		return fmt.Errorf("published-at: %w", err)
	}

	privateKey, err := loadPrivateKey(*keyPath)
	if err != nil {
		return err
	}
	digest, size, err := hashFile(*packagePath)
	if err != nil {
		return err
	}
	if size <= 0 || size > 1_000_000_000 {
		return errors.New("package size must be between 1 byte and 1 GB")
	}
	m := manifest{
		Schema: 2, Platform: "macos", Version: *version,
		MinimumSystemVersion: *minimum, URL: *packageURL,
		SHA256: digest, Size: size, PublishedAt: when,
	}
	m.Signature = base64.StdEncoding.EncodeToString(ed25519.Sign(privateKey, canonical(m)))
	pqPrivate, err := loadMLDSAPrivateKey(*keyPath + ".mldsa65")
	if err != nil {
		return err
	}
	pqSignature := make([]byte, mldsa65.SignatureSize)
	if err := mldsa65.SignTo(pqPrivate, canonical(m), []byte("RatelMesh-Update-v1"), false, pqSignature); err != nil {
		return err
	}
	m.PQSignature = base64.StdEncoding.EncodeToString(pqSignature)
	data, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return err
	}
	data = append(data, '\n')
	if err := os.MkdirAll(filepath.Dir(*output), 0o755); err != nil {
		return err
	}
	return os.WriteFile(*output, data, 0o644)
}

func writeMLDSASeed(path string, privateKey *mldsa65.PrivateKey) error {
	seed := privateKey.Seed()
	if len(seed) != mldsa65.SeedSize {
		return errors.New("ML-DSA key has no seed")
	}
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	if _, err := file.WriteString(base64.StdEncoding.EncodeToString(seed) + "\n"); err != nil {
		file.Close()
		return err
	}
	return file.Close()
}

func loadMLDSAPrivateKey(path string) (*mldsa65.PrivateKey, error) {
	info, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() || info.Mode().Perm()&0o077 != 0 {
		return nil, errors.New("ML-DSA release key must be a regular file with mode 0600")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	seedBytes, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(data)))
	if err != nil || len(seedBytes) != mldsa65.SeedSize {
		return nil, errors.New("invalid ML-DSA release key")
	}
	var seed [mldsa65.SeedSize]byte
	copy(seed[:], seedBytes)
	_, privateKey := mldsa65.NewKeyFromSeed(&seed)
	return privateKey, nil
}

func loadPrivateKey(path string) (ed25519.PrivateKey, error) {
	info, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() || info.Mode().Perm()&0o077 != 0 {
		return nil, errors.New("release key must be a regular file with mode 0600")
	}
	seedText, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	seed, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(seedText)))
	if err != nil || len(seed) != ed25519.SeedSize {
		return nil, errors.New("invalid release key")
	}
	return ed25519.NewKeyFromSeed(seed), nil
}

func canonical(m manifest) []byte {
	return []byte(strings.Join([]string{
		"schema=" + strconv.Itoa(m.Schema),
		"platform=" + m.Platform,
		"version=" + m.Version,
		"minimumSystemVersion=" + m.MinimumSystemVersion,
		"url=" + m.URL,
		"sha256=" + m.SHA256,
		"size=" + strconv.FormatInt(m.Size, 10),
		"publishedAt=" + m.PublishedAt,
		"",
	}, "\n"))
}

func hashFile(path string) (string, int64, error) {
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

func validVersion(value string, allowedCounts ...int) bool {
	parts := strings.Split(value, ".")
	allowed := false
	for _, count := range allowedCounts {
		allowed = allowed || len(parts) == count
	}
	if !allowed {
		return false
	}
	for _, part := range parts {
		if part == "" || len(part) > 6 || (len(part) > 1 && part[0] == '0') {
			return false
		}
		for _, char := range part {
			if char < '0' || char > '9' {
				return false
			}
		}
	}
	return true
}

func validPackageURL(raw, version string) bool {
	parsed, err := url.Parse(raw)
	if err != nil {
		return false
	}
	expectedPath := "/download/RatelMesh-macOS-" + version + "-universal.pkg"
	return parsed.Scheme == "https" &&
		parsed.Host == "download.ratelmesh.com" &&
		parsed.User == nil &&
		parsed.Path == expectedPath &&
		parsed.RawPath == "" &&
		parsed.RawQuery == "" &&
		!parsed.ForceQuery &&
		parsed.Fragment == ""
}

func validPublishedAt(value string) error {
	// Foundation's default ISO8601DateFormatter accepts whole-second RFC3339 but
	// rejects fractional seconds. Reject them before signing so a syntactically
	// valid Go timestamp cannot make the Swift updater discard the manifest.
	if strings.Contains(value, ".") {
		return errors.New("fractional seconds are not supported")
	}
	if _, err := time.Parse(time.RFC3339, value); err != nil {
		return err
	}
	return nil
}

func fatal(err error) {
	fmt.Fprintln(os.Stderr, "update-manifest:", err)
	os.Exit(1)
}
