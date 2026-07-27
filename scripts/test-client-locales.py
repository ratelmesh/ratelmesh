#!/usr/bin/env python3
"""Verify that every RatelMesh client ships the same supported languages."""

from __future__ import annotations

import json
import re
import sys
import xml.etree.ElementTree as ET
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
LOCALES = ("en", "es", "de", "fr", "ja", "ko", "it", "nl", "pl", "sv", "pt-BR", "zh-CN", "zh-TW")
INTERNAL_FILES = {
    "en": "en", "es": "es", "de": "de", "fr": "fr", "ja": "ja", "ko": "ko",
    "it": "it", "nl": "nl", "pl": "pl", "sv": "sv", "pt-BR": "pt-BR",
    "zh-CN": "zh-Hans", "zh-TW": "zh-Hant",
}
ANDROID_DIRS = {
    "en": "values", "es": "values-es", "de": "values-de", "fr": "values-fr",
    "ja": "values-ja", "ko": "values-ko", "it": "values-it", "nl": "values-nl",
    "pl": "values-pl", "sv": "values-sv", "pt-BR": "values-pt-rBR",
    "zh-CN": "values-zh-rCN", "zh-TW": "values-zh-rTW",
}
APPLE_DIRS = {
    "es": "es", "de": "de", "fr": "fr", "ja": "ja", "ko": "ko", "it": "it",
    "nl": "nl", "pl": "pl", "sv": "sv", "pt-BR": "pt-BR",
    "zh-CN": "zh-Hans", "zh-TW": "zh-Hant",
}


def fail(message: str) -> None:
    print(f"client locale check: {message}", file=sys.stderr)
    raise SystemExit(1)


def json_catalog(path: Path) -> dict[str, str]:
    if not path.is_file():
        fail(f"missing {path.relative_to(ROOT)}")
    value = json.loads(path.read_text())
    if not isinstance(value, dict):
        fail(f"{path.relative_to(ROOT)} is not a JSON object")
    catalog = {key: item for key, item in value.items() if key != "_meta"}
    if any(not isinstance(item, str) for item in catalog.values()):
        fail(f"{path.relative_to(ROOT)} contains a non-string message")
    return catalog


def android_catalog(directory: Path) -> dict[str, str]:
    if not directory.is_dir():
        fail(f"missing {directory.relative_to(ROOT)}")
    catalog: dict[str, str] = {}
    files = sorted(directory.glob("*.xml"))
    if not files:
        fail(f"{directory.relative_to(ROOT)} has no resource catalogs")
    for path in files:
        for node in ET.parse(path).getroot().findall("string"):
            key = node.attrib["name"]
            if key in catalog:
                fail(f"duplicate Android key {key!r} in {path.relative_to(ROOT)}")
            catalog[key] = "".join(node.itertext())
    return catalog


def placeholders(value: str) -> tuple[str, ...]:
    brace = re.findall(r"\{[A-Za-z][A-Za-z0-9_]*\}", value)
    printf = re.findall(r"(?<!%)%(?:\d+\$)?[@a-zA-Z]", value)
    return tuple(sorted(brace + printf))


def verify_catalog(reference: dict[str, str], candidate: dict[str, str], label: str) -> None:
    if set(candidate) != set(reference):
        fail(f"{label} keys differ: missing={sorted(set(reference)-set(candidate))}, extra={sorted(set(candidate)-set(reference))}")
    for key, value in candidate.items():
        if placeholders(value) != placeholders(reference[key]):
            fail(f"{label} placeholder mismatch for {key!r}")


def strings_file(path: Path) -> dict[str, str]:
    if not path.is_file():
        fail(f"missing {path.relative_to(ROOT)}")
    entries: dict[str, str] = {}
    pattern = re.compile(r'^\s*"((?:\\.|[^"])*)"\s*=\s*"((?:\\.|[^"])*)";\s*$')
    for number, line in enumerate(path.read_text().splitlines(), 1):
        if not line.strip() or line.lstrip().startswith(("/*", "*", "//")):
            continue
        match = pattern.match(line)
        if not match:
            fail(f"invalid .strings entry at {path.relative_to(ROOT)}:{number}")
        key, value = match.groups()
        if key in entries:
            fail(f"duplicate key {key!r} in {path.relative_to(ROOT)}")
        entries[key] = value
    return entries


base_internal = json_catalog(ROOT / "internal/i18n/locales/en.json")
for locale, filename in INTERNAL_FILES.items():
    verify_catalog(base_internal, json_catalog(ROOT / f"internal/i18n/locales/{filename}.json"), f"internal {locale}")

base_android = android_catalog(ROOT / "clients/android/app/src/main/res/values")
for locale, dirname in ANDROID_DIRS.items():
    verify_catalog(base_android, android_catalog(ROOT / f"clients/android/app/src/main/res/{dirname}"), f"Android {locale}")

android_namespace = "{http://schemas.android.com/apk/res/android}"
configured_android = tuple(
    node.attrib[f"{android_namespace}name"]
    for node in ET.parse(ROOT / "clients/android/app/src/main/res/xml/locales_config.xml").getroot().findall("locale")
)
if configured_android != LOCALES:
    fail(f"Android locales_config.xml differs: got={configured_android}, want={LOCALES}")

apple_catalogs: dict[Path, set[str]] = {}
for root in (ROOT / "clients/macos-menubar/Localizations", ROOT / "clients/ios/RatelMesh"):
    reference: set[str] | None = None
    for locale, dirname in APPLE_DIRS.items():
        entries: dict[str, str] = {}
        for filename in ("Localizable.strings", "NetworkDoctor.strings"):
            catalog = strings_file(root / f"{dirname}.lproj/{filename}")
            duplicate = set(entries) & set(catalog)
            conflicting = {key for key in duplicate if entries[key] != catalog[key]}
            if conflicting:
                fail(f"{root.relative_to(ROOT)} {locale} conflicts in {filename}: {sorted(conflicting)}")
            entries.update(catalog)
        keys = set(entries)
        if reference is None:
            reference = keys
        elif keys != reference:
            fail(f"{root.relative_to(ROOT)} {locale} keys differ")
        for key, value in entries.items():
            if key.count("%@") != value.count("%@"):
                fail(f"{root.relative_to(ROOT)} {locale} placeholder mismatch for {key!r}")
    apple_catalogs[root] = reference or set()

mac_source = "\n".join(
    (ROOT / f"clients/macos-menubar/{filename}").read_text()
    for filename in ("RatelMeshMenuApp.swift", "UpdateSupport.swift")
)
mac_keys = set(re.findall(r'Copy\.(?:text|format)\(\s*"((?:\\.|[^"])*)"\s*,', mac_source))
mac_keys.update(re.findall(r'UpdateCopy\.(?:text|format)\(\s*"((?:\\.|[^"])*)"\s*,', mac_source))
missing_mac = mac_keys - apple_catalogs[ROOT / "clients/macos-menubar/Localizations"]
if missing_mac:
    fail(f"macOS catalogs miss UI keys: {sorted(missing_mac)}")

ios_source = (ROOT / "clients/ios/RatelMesh/ContentView.swift").read_text()
ios_keys = set(re.findall(r'\b[tf]\(\s*"(?:\\.|[^"])*"\s*,\s*"((?:\\.|[^"])*)"', ios_source))
missing_ios = ios_keys - apple_catalogs[ROOT / "clients/ios/RatelMesh"]
if missing_ios:
    fail(f"iOS catalogs miss UI keys: {sorted(missing_ios)}")

android_language = (ROOT / "clients/android/app/src/main/java/com/ratelmesh/android/AppLanguage.kt").read_text()
ios_language = (ROOT / "clients/ios/Shared/ProductLanguage.swift").read_text()
mac_language = mac_source
android_selector = set(re.findall(r'^[ \t]*[A-Z_]+\("([^"]+)"\)', android_language, re.MULTILINE))
if android_selector != set(LOCALES) | {"system"}:
    fail(f"Android language selector differs: got={sorted(android_selector)}")
apple_expected = {"es", "de", "fr", "ja", "ko", "it", "nl", "pl", "sv", "pt-BR", "zh-Hant"}
for label, source in (("iOS", ios_language), ("macOS", mac_language)):
    selector = set(re.findall(r'case\s+\w+\s*=\s*"([^"]+)"', source))
    missing = apple_expected - selector
    if missing:
        fail(f"{label} language selector misses {sorted(missing)}")

print(f"client locale check passed: {len(LOCALES)} languages across CLI, Android, macOS and iOS/iPadOS")
