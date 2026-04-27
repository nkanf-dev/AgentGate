package scanner

import "testing"

func TestDetectAndRewriteSecrets(t *testing.T) {
	input := "deploy with api_key: sk-test-1234567890abcdef and continue"

	findings := DetectSecrets(input)
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	if findings[0].Value != "sk-test-1234567890abcdef" {
		t.Fatalf("unexpected finding value %q", findings[0].Value)
	}

	rewritten := RewriteSecrets(input, findings, func(index int, _ SecretFinding) string {
		return "[SECRET_HANDLE:1]"
	})
	if rewritten == input {
		t.Fatal("expected rewritten text to change")
	}
	if rewritten != "deploy with api_key: [SECRET_HANDLE:1] and continue" {
		t.Fatalf("unexpected rewrite %q", rewritten)
	}
}

func TestHashSecretDoesNotReturnRawValue(t *testing.T) {
	secret := "sk-test-1234567890abcdef"
	hash := HashSecret(secret)
	if hash == "" {
		t.Fatal("expected hash")
	}
	if hash == secret {
		t.Fatal("hash must not equal raw secret")
	}
}
