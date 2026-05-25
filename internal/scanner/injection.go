package scanner

import (
	"context"
	"encoding/base64"
	"regexp"
	"strings"
	"unicode"
	"unicode/utf8"
)

type InjectionFinding struct {
	Kind  string
	Start int
	End   int
	Value string
}

type InjectionDetector interface {
	DetectInjections(ctx context.Context, text string) ([]InjectionFinding, error)
}

type injectionPattern struct {
	kind    string
	pattern *regexp.Regexp
}

var injectionPatterns = []injectionPattern{
	{
		kind:    "prompt_injection",
		pattern: regexp.MustCompile(`(?i)\bignore\s+(all\s+)?(previous|prior|earlier)\s+(instructions|rules|prompts|context)\b`),
	},
	{
		kind:    "prompt_injection",
		pattern: regexp.MustCompile(`(?i)\byou\s+are\s+now\s+(an?\s+)?(unrestricted|unfiltered|uncensored|DAN)\b`),
	},
	{
		kind:    "prompt_injection",
		pattern: regexp.MustCompile(`(?i)\bnew\s+instructions?\s*:`),
	},
	{
		kind:    "prompt_injection",
		pattern: regexp.MustCompile(`(?i)\bforget\s+(all\s+)?(your\s+)?(instructions|rules|guidelines|training)\b`),
	},
	{
		kind:    "prompt_injection",
		pattern: regexp.MustCompile(`(?i)\bdisregard\s+(all\s+)?(previous|prior|earlier)\s+(instructions|rules|context)\b`),
	},
	{
		kind: "embedded_instruction",
		// XML-like pseudo-tags that could override system instructions.
		pattern: regexp.MustCompile(`(?i)<\s*(system|instructions?|prompt)\s*>`),
	},
	{
		kind:    "role_play",
		pattern: regexp.MustCompile(`(?i)\bpretend\s+you\s+are\s+(an?\s+)?(AI|assistant|model)\s+(without|with\s+no)\s+(restrictions|guidelines|rules|limits)\b`),
	},
	{
		kind:    "role_play",
		pattern: regexp.MustCompile(`(?i)\bact\s+as\s+(if|though)\s+you\s+(have|are)\s+(no|without)\s+(guidelines|rules|restrictions|limitations)\b`),
	},
	{
		kind:    "role_play",
		pattern: regexp.MustCompile(`(?i)\benable\s+DAN\s+mode\b`),
	},
	{
		kind:    "role_play",
		pattern: regexp.MustCompile(`(?i)\bjailbreak\b`),
	},
}

// base64MinLength is the minimum length for a string to be considered a
// suspicious base64 block. 60 chars ≈ 45 bytes of decoded content.
const base64MinLength = 60

// RegexInjectionDetector implements InjectionDetector using regex patterns.
type RegexInjectionDetector struct{}

func (RegexInjectionDetector) DetectInjections(ctx context.Context, text string) ([]InjectionFinding, error) {
	return DetectInjections(text), nil
}

func DetectInjections(text string) []InjectionFinding {
	if strings.TrimSpace(text) == "" {
		return nil
	}

	findings := make([]InjectionFinding, 0)

	// Regex patterns.
	for _, pat := range injectionPatterns {
		matches := pat.pattern.FindAllStringIndex(text, -1)
		for _, loc := range matches {
			findings = append(findings, InjectionFinding{
				Kind:  pat.kind,
				Start: loc[0],
				End:   loc[1],
				Value: text[loc[0]:loc[1]],
			})
		}
	}

	// Base64 blocks with decode verification.
	findings = append(findings, detectBase64Blocks(text)...)

	// Zero-width characters.
	findings = append(findings, detectZeroWidth(text)...)

	return dedupeInjectionOverlaps(findings)
}

// base64Pattern matches sequences of base64 characters that look like encoded
// blocks (with optional padding).
var base64Pattern = regexp.MustCompile(`[A-Za-z0-9+/]{` + itoa(base64MinLength) + `,}={0,3}`)

func detectBase64Blocks(text string) []InjectionFinding {
	matches := base64Pattern.FindAllStringIndex(text, -1)
	var findings []InjectionFinding
	for _, loc := range matches {
		block := text[loc[0]:loc[1]]
		decoded, err := base64.StdEncoding.DecodeString(block)
		if err != nil {
			// Try raw base64 (no padding).
			decoded, err = base64.RawStdEncoding.DecodeString(block)
			if err != nil {
				continue
			}
		}
		if !utf8.Valid(decoded) {
			continue
		}
		// Check if decoded content contains readable text (at least 60% letters).
		if !containsReadableText(decoded) {
			continue
		}
		findings = append(findings, InjectionFinding{
			Kind:  "embedded_instruction",
			Start: loc[0],
			End:   loc[1],
			Value: block,
		})
	}
	return findings
}

func containsReadableText(data []byte) bool {
	letters := 0
	for _, r := range string(data) {
		if unicode.IsLetter(r) || unicode.IsSpace(r) {
			letters++
		}
	}
	return len(data) > 0 && float64(letters)/float64(len(data)) > 0.6
}

// zero-width characters that could be used to hide instructions.
var zeroWidthPattern = regexp.MustCompile("[\u200B\u200C\u200D\u200E\u200F\u202A\u202B\u202C\u202D\u202E\u2060\u2061\u2062\u2063\u2064\uFEFF]+")

func detectZeroWidth(text string) []InjectionFinding {
	matches := zeroWidthPattern.FindAllStringIndex(text, -1)
	var findings []InjectionFinding
	for _, loc := range matches {
		findings = append(findings, InjectionFinding{
			Kind:  "embedded_instruction",
			Start: loc[0],
			End:   loc[1],
			Value: text[loc[0]:loc[1]],
		})
	}
	return findings
}

func dedupeInjectionOverlaps(findings []InjectionFinding) []InjectionFinding {
	if len(findings) <= 1 {
		return findings
	}
	// Sort by start position, then by longest match.
	for i := 1; i < len(findings); i++ {
		for j := i; j > 0 && (findings[j].Start < findings[j-1].Start ||
			(findings[j].Start == findings[j-1].Start && findings[j].End > findings[j-1].End)); j-- {
			findings[j], findings[j-1] = findings[j-1], findings[j]
		}
	}
	result := make([]InjectionFinding, 0, len(findings))
	lastEnd := -1
	for _, f := range findings {
		if f.Start < lastEnd {
			continue
		}
		result = append(result, f)
		lastEnd = f.End
	}
	return result
}

// itoa is a minimal int-to-string helper to avoid importing strconv for a
// single format use in a const context.
func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	s := ""
	for n > 0 {
		s = string(rune('0'+n%10)) + s
		n /= 10
	}
	return s
}
