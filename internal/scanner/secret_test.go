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

func TestDetectAWSAccessKey(t *testing.T) {
	input := "export AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE"
	findings := DetectSecrets(input)
	var found bool
	for _, f := range findings {
		if f.Kind == "aws_access_key" {
			found = true
			if f.Value != "AKIAIOSFODNN7EXAMPLE" {
				t.Fatalf("unexpected value %q", f.Value)
			}
		}
	}
	if !found {
		t.Fatalf("expected aws_access_key finding, got %#v", findings)
	}
}

func TestDetectGitHubToken(t *testing.T) {
	input := "token: ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij"
	findings := DetectSecrets(input)
	var found bool
	for _, f := range findings {
		if f.Kind == "github_token" {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected github_token finding, got %#v", findings)
	}
}

func TestDetectSlackToken(t *testing.T) {
	input := "key=xoxb-123456789012-1234567890123-abcdefghij"
	findings := DetectSecrets(input)
	var found bool
	for _, f := range findings {
		if f.Kind == "slack_token" {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected slack_token finding, got %#v", findings)
	}
}

func TestDetectJWT(t *testing.T) {
	// Minimal 3-part base64 token structure.
	input := "auth=eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U"
	findings := DetectSecrets(input)
	var found bool
	for _, f := range findings {
		if f.Kind == "jwt" {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected jwt finding, got %#v", findings)
	}
}
