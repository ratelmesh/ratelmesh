package main

import "testing"

func TestParseGlobalLanguageOption(t *testing.T) {
	args, language, err := parseGlobalOptions([]string{"--lang", "zh-Hans", "status", "--json"})
	if err != nil || language != "zh-Hans" || len(args) != 2 || args[0] != "status" || args[1] != "--json" {
		t.Fatalf("args=%q language=%q err=%v", args, language, err)
	}
	args, language, err = parseGlobalOptions([]string{"--lang=ja", "exit", "list"})
	if err != nil || language != "ja" || len(args) != 2 || args[0] != "exit" {
		t.Fatalf("args=%q language=%q err=%v", args, language, err)
	}
}

func TestParseGlobalLanguageRequiresValue(t *testing.T) {
	if _, _, err := parseGlobalOptions([]string{"--lang"}); err == nil {
		t.Fatal("expected missing language error")
	}
}
