package main

import "testing"

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
