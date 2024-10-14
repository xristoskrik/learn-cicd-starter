package auth

import (
	"net/http"
	"testing"
)

func TestGetAPIKey_NoHeader(t *testing.T) {
	headers := http.Header{}

	_, err := GetAPIKey(headers)
	if err != ErrNoAuthHeaderIncluded {
		t.Errorf("expected error: %v, got: %v", ErrNoAuthHeaderIncluded, err)
	}
}

func TestGetAPIKey_MalformedHeader(t *testing.T) {
	headers := http.Header{}
	headers.Set("Authorization", "Bearer xyz")

	_, err := GetAPIKey(headers)
	if err == nil || err.Error() != "malformed authorization header" {
		t.Errorf("expected malformed authorization header error, got: %v", err)
	}
}

func TestGetAPIKey_ValidHeader(t *testing.T) {
	headers := http.Header{}
	headers.Set("Authorization", "ApiKey abc123")

	apiKey, err := GetAPIKey(headers)
	if err != nil {
		t.Errorf("expected no error, got: %v", err)
	}
	if apiKey != "abc123" {
		t.Errorf("expected API key: abc123, got: %v", apiKey)
	}
}
