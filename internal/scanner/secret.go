package scanner

import (
	"crypto/sha256"
	"encoding/hex"
	"log"
	"regexp"
	"sort"
	"strings"
)

type SecretFinding struct {
	Kind  string
	Start int
	End   int
	Value string
}

// Detector is the common interface for secret detection backends.
type Detector interface {
	DetectSecrets(text string) ([]SecretFinding, error)
}

type regexPattern struct {
	kind       string
	pattern    *regexp.Regexp
	valueGroup int
}

var secretDetectors = []regexPattern{
	{
		kind:       "openai_api_key",
		pattern:    regexp.MustCompile(`\bsk-[A-Za-z0-9_-]{16,}\b`),
		valueGroup: 0,
	},
	{
		kind:       "generic_api_key",
		pattern:    regexp.MustCompile(`(?i)\b(api[_-]?key|token|secret|password)\b\s*[:=]\s*([A-Za-z0-9_./+=-]{8,})`),
		valueGroup: 2,
	},
}

// RegexDetector implements Detector using regex patterns.
type RegexDetector struct{}

func (RegexDetector) DetectSecrets(text string) ([]SecretFinding, error) {
	return DetectSecrets(text), nil
}

// CompositeDetector tries an ML detector first and falls back to regex on
// any error.  Findings from both are merged and deduplicated.
type CompositeDetector struct {
	ML    Detector
	Regex Detector
}

func (c *CompositeDetector) DetectSecrets(text string) ([]SecretFinding, error) {
	mlFindings, mlErr := c.ML.DetectSecrets(text)
	if mlErr != nil {
		log.Printf("ml scanner error, falling back to regex: %v", mlErr)
		return c.Regex.DetectSecrets(text)
	}

	regexFindings, regexErr := c.Regex.DetectSecrets(text)
	if regexErr != nil {
		return mlFindings, nil
	}

	merged := append(mlFindings, regexFindings...)
	return dedupeOverlaps(merged), nil
}

// DetectSecrets is the package-level regex scanner (backward compatible).
func DetectSecrets(text string) []SecretFinding {
	findings := make([]SecretFinding, 0)
	for _, det := range secretDetectors {
		matches := det.pattern.FindAllStringSubmatchIndex(text, -1)
		for _, match := range matches {
			groupStart := det.valueGroup * 2
			groupEnd := groupStart + 1
			if groupEnd >= len(match) || match[groupStart] < 0 || match[groupEnd] < 0 {
				continue
			}
			findings = append(findings, SecretFinding{
				Kind:  det.kind,
				Start: match[groupStart],
				End:   match[groupEnd],
				Value: text[match[groupStart]:match[groupEnd]],
			})
		}
	}
	return dedupeOverlaps(findings)
}

func RewriteSecrets(text string, findings []SecretFinding, placeholder func(index int, finding SecretFinding) string) string {
	if len(findings) == 0 {
		return text
	}

	var builder strings.Builder
	builder.Grow(len(text))
	last := 0
	for index, finding := range findings {
		if finding.Start < last {
			continue
		}
		builder.WriteString(text[last:finding.Start])
		builder.WriteString(placeholder(index, finding))
		last = finding.End
	}
	builder.WriteString(text[last:])
	return builder.String()
}

func HashSecret(value string) string {
	sum := sha256.Sum256([]byte(value))
	return hex.EncodeToString(sum[:])
}

func dedupeOverlaps(findings []SecretFinding) []SecretFinding {
	sort.Slice(findings, func(i, j int) bool {
		if findings[i].Start == findings[j].Start {
			return findings[i].End > findings[j].End
		}
		return findings[i].Start < findings[j].Start
	})

	result := make([]SecretFinding, 0, len(findings))
	lastEnd := -1
	for _, finding := range findings {
		if finding.Start < lastEnd {
			continue
		}
		result = append(result, finding)
		lastEnd = finding.End
	}
	return result
}
