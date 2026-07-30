package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func readReleaseFile(t *testing.T, path ...string) string {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(path...))
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
}

func TestPublicClientBundlesExcludePrivateRelay(t *testing.T) {
	for _, path := range [][]string{
		{"build-desktop-release.sh"},
		{"..", "clients", "windows", "Package.ps1"},
	} {
		source := readReleaseFile(t, path...)
		if strings.Contains(source, "ratelmesh-relay") {
			t.Fatalf("%s packages the private Relay service", filepath.Join(path...))
		}
	}
}

func TestMacOSReleaseDoesNotDeleteCallerOutputDirectory(t *testing.T) {
	source := readReleaseFile(t, "release-macos.sh")
	if strings.Contains(source, `rm -rf "$OUTDIR"`) {
		t.Fatal("release-macos.sh recursively deletes a caller-controlled path")
	}
	if !strings.Contains(source, `if [[ -e "$OUTDIR" ]]`) {
		t.Fatal("release-macos.sh does not reject an existing output path")
	}
}

func TestReleaseBuildersDoNotRecursivelyDeleteCallerPaths(t *testing.T) {
	for _, tc := range []struct {
		path      []string
		forbidden string
	}{
		{path: []string{"build-macos-dependencies.sh"}, forbidden: `rm -rf "$OUT"`},
		{path: []string{"..", "clients", "windows", "Package.ps1"}, forbidden: "Remove-Item -LiteralPath $bundle -Recurse"},
	} {
		source := readReleaseFile(t, tc.path...)
		if strings.Contains(source, tc.forbidden) {
			t.Fatalf("%s recursively deletes a caller-derived path: %s", filepath.Join(tc.path...), tc.forbidden)
		}
	}
}

func TestMacOSBuildersRefuseExistingOrLinkedOutputs(t *testing.T) {
	for _, tc := range []struct {
		path     string
		required []string
	}{
		{
			path: "build-macos-update.sh",
			required: []string{
				`[[ -L "$OUTDIR" ]]`,
				`[[ -e "$PKG" || -L "$PKG" ]]`,
				"macOS update package must not already exist",
				`mktemp -d "$OUTDIR/.ratelmesh-macos-update.XXXXXX"`,
				`pkgbuild`,
				`"$STAGED_PKG"`,
				`ln "$STAGED_PKG" "$PKG"`,
			},
		},
		{
			path: "build-macos-installer.sh",
			required: []string{
				`[ -e "$OUTPUT" ] || [ -L "$OUTPUT" ]`,
				"installer output must not already exist",
				`mktemp -d "$OUTPUT_DIR/.ratelmesh-installer.XXXXXX"`,
				`"$STAGED_OUTPUT"`,
				`ln "$STAGED_OUTPUT" "$OUTPUT_ABS"`,
			},
		},
	} {
		source := readReleaseFile(t, tc.path)
		for _, required := range tc.required {
			if !strings.Contains(source, required) {
				t.Errorf("%s does not fail closed on caller output %q", tc.path, required)
			}
		}
	}
}

func TestMacOSBuildersUseCanonicalNumericBundleBuild(t *testing.T) {
	for _, path := range []string{"build-macos-update.sh", "build-macos-installer.sh"} {
		source := readReleaseFile(t, path)
		for _, required := range []string{
			"clients/macos-menubar/Info.plist",
			"CFBundleVersion",
			"positive integer without leading zeros",
			`-string "$BUNDLE_BUILD"`,
			`plutil -extract CFBundleVersion raw`,
		} {
			if !strings.Contains(source, required) {
				t.Errorf("%s does not bind the packaged build number to canonical metadata %q", path, required)
			}
		}
		for _, forbidden := range []string{`"${VERSION//./}"`, `tr -d '.'`} {
			if strings.Contains(source, forbidden) {
				t.Errorf("%s still derives an ambiguous build number with %q", path, forbidden)
			}
		}
	}

	installerTest := readReleaseFile(t, "test-macos-universal-installer.sh")
	if !strings.Contains(installerTest, `plutil -extract CFBundleVersion raw`) ||
		!strings.Contains(installerTest, `= "$EXPECTED_BUILD"`) {
		t.Fatal("universal installer test does not assert the packaged CFBundleVersion")
	}
}

func TestLinuxServiceKeepsEnrollmentSecretOutOfArgv(t *testing.T) {
	service := readReleaseFile(t, "..", "clients", "linux", "ratelmeshd.service")
	if strings.Contains(service, "-authkey") || strings.Contains(service, "${RATELMESH_AUTHKEY}") {
		t.Fatal("Linux service exposes its enrollment credential in process argv")
	}
	for _, required := range []string{
		"EnvironmentFile=/etc/ratelmesh/client.env",
		"StartLimitIntervalSec=0",
		"CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_RAW CAP_NET_BIND_SERVICE",
		"NoNewPrivileges=true",
		"UMask=0077",
		"StateDirectoryMode=0700",
		"RuntimeDirectoryMode=0700",
		"-socket /run/ratelmeshd/ratelmeshd.sock",
	} {
		if !strings.Contains(service, required) {
			t.Errorf("Linux service is missing lifecycle hardening %q", required)
		}
	}
	readme := readReleaseFile(t, "..", "clients", "linux", "README.md")
	if strings.Contains(readme, "v0.2.7") || strings.Contains(readme, "`ratelmesh-relay`") {
		t.Fatal("Linux package documentation describes stale or absent contents")
	}
}

func TestDesktopUninstallersUseExactRouteOwnership(t *testing.T) {
	windows := readReleaseFile(t, "..", "clients", "windows", "Uninstall-RatelMesh.ps1")
	for _, required := range []string{
		"route-owners-v1.json",
		"-InterfaceIndex $interfaceIndex",
		"Where-Object { $_.NextHop -eq [string]$route.NextHop }",
		"Remove-NetRoute -InputObject $entry",
		"WireGuardTunnel$ratelmesh0",
		"installation files and state were retained for a safe retry",
	} {
		if !strings.Contains(windows, required) {
			t.Errorf("Windows uninstaller is missing exact-owner cleanup %q", required)
		}
	}
	if strings.Contains(windows, "Remove-NetRoute -DestinationPrefix") {
		t.Fatal("Windows uninstaller contains a prefix-only route delete")
	}

	mac := readReleaseFile(t, "..", "packaging", "macos", "installer", "ratelmesh-uninstall")
	for _, forbidden := range []string{
		"route -n delete -net 0.0.0.0/1",
		"route -n delete -net 128.0.0.0/1",
		"route -n delete -inet6 -net ::/1",
		"route -n delete -inet6 -net 8000::/1",
		`plutil -p "$PLIST"`,
		"sysctl -w net.inet.ip.forwarding=0",
	} {
		if strings.Contains(mac, forbidden) {
			t.Errorf("macOS uninstaller contains unsafe global cleanup %q", forbidden)
		}
	}
	for _, required := range []string{
		"route-owners-v1.json",
		`"$destination" -interface "$device"`,
		"ratelmesh-killswitch.pf.conf",
		"PF_NAT_OWNED",
		"pfctl -f /etc/pf.conf",
	} {
		if !strings.Contains(mac, required) {
			t.Errorf("macOS uninstaller is missing ownership-gated cleanup %q", required)
		}
	}
}

func TestWindowsUpgradePreservesConfigurationAndRecoveryTask(t *testing.T) {
	installer := readReleaseFile(t, "..", "clients", "windows", "Install-RatelMesh.ps1")
	for _, required := range []string{
		"Existing RatelMesh configuration is unreadable; no service or file was changed",
		"$PSBoundParameters.ContainsKey('KillSwitch')",
		"$PSBoundParameters.ContainsKey('TunnelDNS')",
		"$PSBoundParameters.ContainsKey('StateDir')",
		"Get-PreviousValue $oldConfig 'AuthKeyProtected' ''",
		"previous RatelMesh daemon did not stop",
		"-RestartCount 999",
		"Register-ScheduledTask -TaskName $taskName",
	} {
		if !strings.Contains(installer, required) {
			t.Errorf("Windows upgrade is missing compatibility/recovery contract %q", required)
		}
	}
	unregister := strings.Index(installer, "Unregister-ScheduledTask")
	rollback := strings.Index(installer, "} catch {")
	restorePrevious := strings.Index(installer, "Register-ScheduledTask -TaskName $taskName -Xml $oldTaskXml")
	if strings.Count(installer, "Unregister-ScheduledTask") != 1 ||
		rollback < 0 || restorePrevious < rollback || unregister < restorePrevious {
		t.Fatal("Windows upgrade may remove its recovery task outside the no-prior-task rollback branch")
	}
}

func TestMacOSReleaseBindsBothIdentitiesToRequiredTeam(t *testing.T) {
	source := readReleaseFile(t, "release-macos.sh")
	for _, required := range []string{
		`APPLE_TEAM_ID="${RATELMESH_APPLE_TEAM_ID:-}"`,
		`release-macos.sh" identity-check requested`,
		`release-macos.sh" identity-check app`,
		`release-macos.sh" identity-check package`,
	} {
		if !strings.Contains(source, required) {
			t.Fatalf("release-macos.sh is missing identity binding %q", required)
		}
	}
	identityCheck := strings.Index(source, `release-macos.sh" identity-check package`)
	notarySubmit := strings.Index(source, "notarytool submit")
	if identityCheck < 0 || notarySubmit < 0 || identityCheck > notarySubmit {
		t.Fatal("package identity must be verified before notarization submission")
	}
	notaryAccepted := strings.Index(source, `release-macos.sh" notary-check`)
	staple := strings.Index(source, "stapler staple")
	manifest := strings.Index(source, `update-manifest.go" sign`)
	if notaryAccepted < 0 || staple < 0 || manifest < 0 ||
		notaryAccepted > staple || staple > manifest {
		t.Fatal("release feed must be generated only after an explicitly accepted notarization result and stapling")
	}
	if !strings.Contains(source, "--wait --output-format json") {
		t.Fatal("notarization result is not captured in a machine-readable final state")
	}
}

func TestMacOSReleaseRequiresExplicitUnnotarizedAuthorization(t *testing.T) {
	source := readReleaseFile(t, "release-macos.sh")
	for _, required := range []string{
		`ALLOW_UNNOTARIZED="${RATELMESH_ALLOW_UNNOTARIZED_RELEASE:-}"`,
		`"$ALLOW_UNNOTARIZED" != "1" && -z "$NOTARY_PROFILE"`,
		`RATELMESH_ALLOW_UNNOTARIZED_RELEASE must be exactly 1 when set`,
		`APPLE_NOTARIZATION="notarized"`,
		`APPLE_NOTARIZATION="not_available"`,
		`publishing a Developer ID-signed package without Apple notarization`,
		`"appleNotarization": "%s"`,
	} {
		if !strings.Contains(source, required) {
			t.Errorf("release-macos.sh lacks unnotarized release control %q", required)
		}
	}
	optIn := strings.Index(source, `if [[ "$ALLOW_UNNOTARIZED" == "1" ]]`)
	manifest := strings.Index(source, `update-manifest.go" sign`)
	if optIn < 0 || manifest < 0 || optIn > manifest {
		t.Fatal("unnotarized authorization must be resolved before the update feed is signed")
	}
}

func TestMacOSReleaseNotaryVerifierFailsClosed(t *testing.T) {
	bin := t.TempDir()
	writeExecutable(t, filepath.Join(bin, "plutil"), `#!/bin/sh
test "$1:$2:$3:$4" = "-extract:status:raw:-o" || exit 2
test "$5" = "-" || exit 2
printf '%s\n' "$MOCK_NOTARY_STATUS"
`)
	result := filepath.Join(t.TempDir(), "notary-result.json")
	if err := os.WriteFile(result, []byte(`{"status":"Accepted"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	run := func(status, path string) error {
		command := exec.Command("bash", "release-macos.sh", "notary-check", path)
		command.Dir = "."
		command.Env = append(os.Environ(),
			"PATH="+bin+string(os.PathListSeparator)+os.Getenv("PATH"),
			"MOCK_NOTARY_STATUS="+status,
		)
		return command.Run()
	}
	if err := run("Accepted", result); err != nil {
		t.Fatalf("Accepted notarization result rejected: %v", err)
	}
	for _, status := range []string{"Invalid", "In Progress", ""} {
		if err := run(status, result); err == nil {
			t.Errorf("notarization status %q was accepted", status)
		}
	}
	link := filepath.Join(t.TempDir(), "notary-result-link.json")
	if err := os.Symlink(result, link); err != nil {
		t.Fatal(err)
	}
	if err := run("Accepted", link); err == nil {
		t.Fatal("symbolic-link notarization result was accepted")
	}
}

func TestDesktopReleaseStagesReproducibleArchivesAndChecksum(t *testing.T) {
	source := readReleaseFile(t, "build-desktop-release.sh")
	for _, required := range []string{
		"SOURCE_DATE_EPOCH",
		"export TZ=UTC",
		"--uid 0 --gid 0 --uname root --gname root",
		"--no-xattrs --no-mac-metadata",
		"/usr/bin/gzip -n",
		"/usr/bin/zip -X",
		"SHA256SUMS-desktop.txt",
		"chmod 0644",
		`output directory must not already exist`,
		`go run "$REPO/scripts/publish-directory"`,
	} {
		if !strings.Contains(source, required) {
			t.Errorf("desktop release is missing reproducibility/recovery control %q", required)
		}
	}
	checksum := strings.Index(source, "SHA256SUMS-desktop.txt")
	publish := strings.LastIndex(source, `go run "$REPO/scripts/publish-directory"`)
	if checksum < 0 || publish < 0 || checksum > publish {
		t.Fatal("desktop artifacts are exposed before their checksum set is complete")
	}
	if strings.Contains(source, `ln "$STAGE/$artifact"`) {
		t.Fatal("desktop artifacts are still published one file at a time")
	}
}

func TestReleaseInputsUseCanonicalVersionsAndFeed(t *testing.T) {
	for _, path := range []string{
		"build-desktop-release.sh",
		"build-macos-installer.sh",
		"build-macos-update.sh",
		"release-macos.sh",
	} {
		source := readReleaseFile(t, path)
		if !strings.Contains(source, "version must use canonical MAJOR.MINOR.PATCH without leading zeros") {
			t.Errorf("%s does not enforce the shared canonical version contract", path)
		}
	}
	update := readReleaseFile(t, "build-macos-update.sh")
	if !strings.Contains(update,
		`[[ "$UPDATE_FEED_URL" != "https://download.ratelmesh.com/download/macos/latest.json" ]]`) {
		t.Fatal("macOS build accepts a non-canonical update feed URL")
	}
}

func TestMacOSReleasePublishesOneCompleteDirectory(t *testing.T) {
	source := readReleaseFile(t, "release-macos.sh")
	for _, required := range []string{
		`STAGE="$(mktemp -d "$OUT_PARENT/.ratelmesh-release.XXXXXX")"`,
		`go run "$REPO/scripts/publish-directory" "$STAGE" "$OUTDIR"`,
		`BUILD-PROVENANCE.json`,
		`SOURCE_COMMIT`,
		`SOURCE_DATE_EPOCH`,
	} {
		if !strings.Contains(source, required) {
			t.Errorf("macOS release lacks atomic provenance control %q", required)
		}
	}
	publish := strings.LastIndex(source, `go run "$REPO/scripts/publish-directory"`)
	manifest := strings.LastIndex(source, `update-manifest.go" sign`)
	if manifest < 0 || publish < manifest {
		t.Fatal("macOS release directory is published before its signed manifest is complete")
	}
}

func TestReleaseBuildersRejectLinkedInputsAndRecordProvenance(t *testing.T) {
	dependencies := readReleaseFile(t, "build-macos-dependencies.sh")
	for _, required := range []string{
		`[[ -L "$TOOLS_ARCHIVE" ]]`,
		`mktemp "$CACHE/.wireguard-tools.XXXXXX"`,
	} {
		if !strings.Contains(dependencies, required) {
			t.Errorf("dependency builder lacks linked/cache race control %q", required)
		}
	}
	if strings.Contains(dependencies, `chmod 700 "$CACHE"`) {
		t.Error("dependency builder changes permissions on a caller-selected cache directory")
	}

	installer := readReleaseFile(t, "build-macos-installer.sh")
	for _, required := range []string{
		`[ ! -f "$UPDATE_PKG" ] || [ -L "$UPDATE_PKG" ]`,
		"update package version does not match requested installer version",
		"update package build does not match canonical bundle build",
	} {
		if !strings.Contains(installer, required) {
			t.Errorf("installer builder lacks stale/linked update rejection %q", required)
		}
	}

	for _, path := range []string{"build-desktop-release.sh", "build-macos-update.sh"} {
		source := readReleaseFile(t, path)
		for _, required := range []string{
			"BUILD-PROVENANCE.json",
			"SOURCE_COMMIT",
			"SOURCE_DATE_EPOCH",
			"source tree must be clean",
			"vcs.revision",
			"vcs.modified=false",
		} {
			if !strings.Contains(source, required) {
				t.Errorf("%s lacks reproducible provenance control %q", path, required)
			}
		}
	}
}

func TestMacOSReleaseIdentityVerifierFailsClosed(t *testing.T) {
	const (
		team      = "ABCDE12345"
		otherTeam = "ZYXWV98765"
		app       = "Developer ID Application: RatelMesh LLC (ABCDE12345)"
		installer = "Developer ID Installer: RatelMesh LLC (ABCDE12345)"
	)
	bin := t.TempDir()
	writeExecutable(t, filepath.Join(bin, "security"), `#!/bin/sh
case "$1" in
  find-identity) printf '  1) HASH "%s"\n' "$MOCK_APP_IDENTITY" ;;
  find-certificate) printf '%s\n' "mock certificate" ;;
  *) exit 2 ;;
esac
`)
	writeExecutable(t, filepath.Join(bin, "codesign"), `#!/bin/sh
printf 'Authority=%s\nTeamIdentifier=%s\n' "$MOCK_APP_IDENTITY" "$MOCK_APP_TEAM" >&2
`)
	writeExecutable(t, filepath.Join(bin, "openssl"), `#!/bin/sh
printf 'subject=CN=%s,OU=%s,O=RatelMesh LLC,C=US\n' "$MOCK_INSTALLER_IDENTITY" "$MOCK_INSTALLER_TEAM"
`)
	writeExecutable(t, filepath.Join(bin, "pkgutil"), `#!/bin/sh
printf 'Package "RatelMesh.pkg":\n   Status: signed\n   Certificate Chain:\n    1. %s\n' "$MOCK_INSTALLER_IDENTITY"
`)
	baseEnv := append(os.Environ(),
		"PATH="+bin+string(os.PathListSeparator)+os.Getenv("PATH"),
		"MOCK_APP_IDENTITY="+app,
		"MOCK_APP_TEAM="+team,
		"MOCK_INSTALLER_IDENTITY="+installer,
		"MOCK_INSTALLER_TEAM="+team,
	)
	runWithEnv := func(extraEnv []string, args ...string) error {
		t.Helper()
		command := exec.Command("bash", append([]string{"release-macos.sh", "identity-check"}, args...)...)
		command.Dir = "."
		command.Env = append(append([]string{}, baseEnv...), extraEnv...)
		return command.Run()
	}
	run := func(args ...string) error { return runWithEnv(nil, args...) }

	if err := run("requested", app, installer, team); err != nil {
		t.Fatalf("matching keychain identities rejected: %v", err)
	}
	if err := run("app", "/tmp/RatelMesh.app", app, team); err != nil {
		t.Fatalf("matching signed app rejected: %v", err)
	}
	if err := run("package", "/tmp/RatelMesh.pkg", installer, team); err != nil {
		t.Fatalf("matching signed package rejected: %v", err)
	}
	for name, args := range map[string][]string{
		"missing team":      {"requested", app, installer, ""},
		"application team":  {"requested", app, installer, otherTeam},
		"installer team":    {"requested", app, "Developer ID Installer: RatelMesh LLC (" + otherTeam + ")", team},
		"wrong class":       {"requested", installer, installer, team},
		"signed app team":   {"app", "/tmp/RatelMesh.app", app, otherTeam},
		"package leaf team": {"package", "/tmp/RatelMesh.pkg", "Developer ID Installer: RatelMesh LLC (" + otherTeam + ")", otherTeam},
	} {
		if err := run(args...); err == nil {
			t.Errorf("%s mismatch was accepted", name)
		}
	}
	if err := runWithEnv(
		[]string{"MOCK_INSTALLER_TEAM=" + otherTeam},
		"requested", app, installer, team,
	); err == nil {
		t.Error("Installer certificate OU mismatch was accepted")
	}
}

func writeExecutable(t *testing.T, path, source string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(source), 0o755); err != nil {
		t.Fatal(err)
	}
}
