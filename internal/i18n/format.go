package i18n

import (
	"fmt"
	"strconv"
	"strings"
)

// expand renders an ICU-subset pattern. Supported forms inside braces:
//
//	{name}                         -> args["name"] stringified
//	{name, plural, one {..} other {..}}  -> plural selection; # -> the number
//
// Nested placeholders inside plural option text are expanded recursively.
func expand(pattern string, args map[string]any, lang string) string {
	var b strings.Builder
	runes := []rune(pattern)
	for i := 0; i < len(runes); {
		if runes[i] == '{' {
			inner, next, ok := readBraces(runes, i)
			if !ok {
				b.WriteRune(runes[i])
				i++
				continue
			}
			b.WriteString(expandArg(inner, args, lang))
			i = next
			continue
		}
		b.WriteRune(runes[i])
		i++
	}
	return b.String()
}

// readBraces returns the content between the '{' at start and its matching '}',
// the index just past the '}', and whether a match was found.
func readBraces(runes []rune, start int) (inner string, next int, ok bool) {
	depth := 0
	for i := start; i < len(runes); i++ {
		switch runes[i] {
		case '{':
			depth++
		case '}':
			depth--
			if depth == 0 {
				return string(runes[start+1 : i]), i + 1, true
			}
		}
	}
	return "", start, false
}

func expandArg(inner string, args map[string]any, lang string) string {
	parts := splitTopComma(inner, 3)
	name := strings.TrimSpace(parts[0])

	// Simple placeholder.
	if len(parts) == 1 {
		if v, ok := args[name]; ok {
			return toString(v)
		}
		return "{" + name + "}"
	}

	// {name, plural, options}
	if len(parts) >= 3 && strings.TrimSpace(parts[1]) == "plural" {
		n := toInt(args[name])
		category := pluralCategory(lang, n)
		options := parsePluralOptions(parts[2])
		text, ok := options[category]
		if !ok {
			text = options["other"]
		}
		// Replace '#' with the number, then expand any nested placeholders.
		text = strings.ReplaceAll(text, "#", strconv.Itoa(n))
		return expand(text, args, lang)
	}

	// Unknown form: leave the raw name.
	if v, ok := args[name]; ok {
		return toString(v)
	}
	return "{" + inner + "}"
}

// splitTopComma splits on commas not nested in braces, up to limit fields.
func splitTopComma(s string, limit int) []string {
	var out []string
	depth, last := 0, 0
	for i, r := range s {
		switch r {
		case '{':
			depth++
		case '}':
			depth--
		case ',':
			if depth == 0 && len(out) < limit-1 {
				out = append(out, s[last:i])
				last = i + 1
			}
		}
	}
	out = append(out, s[last:])
	return out
}

// parsePluralOptions parses "one {text} other {text} =0 {text}" into a map.
func parsePluralOptions(s string) map[string]string {
	opts := map[string]string{}
	runes := []rune(s)
	i := 0
	for i < len(runes) {
		// Skip whitespace.
		for i < len(runes) && (runes[i] == ' ' || runes[i] == '\t' || runes[i] == '\n') {
			i++
		}
		// Read a category token up to '{'.
		start := i
		for i < len(runes) && runes[i] != '{' {
			i++
		}
		if i >= len(runes) {
			break
		}
		cat := strings.TrimSpace(string(runes[start:i]))
		text, next, ok := readBraces(runes, i)
		if !ok {
			break
		}
		if cat != "" {
			opts[cat] = text
		}
		i = next
	}
	return opts
}

// pluralCategory returns the CLDR-ish plural category for a count. This covers
// the languages RatelMesh ships: English-like (one/other) and CJK (other only).
func pluralCategory(lang string, n int) string {
	switch lang {
	case "zh", "ja", "ko", "vi", "th":
		return "other" // no singular/plural distinction
	default:
		if n == 1 {
			return "one"
		}
		return "other"
	}
}

func toString(v any) string {
	switch x := v.(type) {
	case string:
		return x
	case fmt.Stringer:
		return x.String()
	default:
		return fmt.Sprintf("%v", v)
	}
}

func toInt(v any) int {
	switch x := v.(type) {
	case int:
		return x
	case int64:
		return int(x)
	case uint64:
		return int(x)
	case float64:
		return int(x)
	default:
		return 0
	}
}
