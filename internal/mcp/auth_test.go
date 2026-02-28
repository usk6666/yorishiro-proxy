package mcp

import (
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestBearerAuthMiddleware(t *testing.T) {
	const validToken = "abc123def456"

	// Dummy handler that records it was called.
	inner := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("ok")) //nolint:errcheck
	})

	handler := BearerAuthMiddleware(inner, validToken)

	tests := []struct {
		name       string
		authHeader string
		wantStatus int
	}{
		{
			name:       "valid_token",
			authHeader: "Bearer abc123def456",
			wantStatus: http.StatusOK,
		},
		{
			name:       "missing_header",
			authHeader: "",
			wantStatus: http.StatusUnauthorized,
		},
		{
			name:       "wrong_token",
			authHeader: "Bearer wrongtoken",
			wantStatus: http.StatusUnauthorized,
		},
		{
			name:       "basic_auth_scheme",
			authHeader: "Basic dXNlcjpwYXNz",
			wantStatus: http.StatusUnauthorized,
		},
		{
			name:       "bearer_lowercase",
			authHeader: "bearer abc123def456",
			wantStatus: http.StatusUnauthorized,
		},
		{
			name:       "empty_bearer_token",
			authHeader: "Bearer ",
			wantStatus: http.StatusUnauthorized,
		},
		{
			name:       "bearer_only_no_space",
			authHeader: "Bearer",
			wantStatus: http.StatusUnauthorized,
		},
		{
			name:       "token_with_extra_spaces",
			authHeader: "Bearer  abc123def456",
			wantStatus: http.StatusUnauthorized,
		},
		{
			name:       "partial_token_prefix",
			authHeader: "Bearer abc123",
			wantStatus: http.StatusUnauthorized,
		},
		{
			name:       "token_with_suffix",
			authHeader: "Bearer abc123def456extra",
			wantStatus: http.StatusUnauthorized,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPost, "/", nil)
			if tt.authHeader != "" {
				req.Header.Set("Authorization", tt.authHeader)
			}
			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, req)

			if rec.Code != tt.wantStatus {
				t.Errorf("status = %d, want %d", rec.Code, tt.wantStatus)
			}

			if tt.wantStatus == http.StatusOK && rec.Body.String() != "ok" {
				t.Errorf("body = %q, want %q", rec.Body.String(), "ok")
			}
		})
	}
}

func TestBearerAuthMiddleware_PassesRequestThrough(t *testing.T) {
	const token = "mytoken"
	var called bool
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		// Verify the original request is forwarded unchanged.
		if r.Method != http.MethodPost {
			t.Errorf("method = %s, want POST", r.Method)
		}
		if r.URL.Path != "/mcp" {
			t.Errorf("path = %s, want /mcp", r.URL.Path)
		}
		w.WriteHeader(http.StatusOK)
	})

	handler := BearerAuthMiddleware(inner, token)
	req := httptest.NewRequest(http.MethodPost, "/mcp", nil)
	req.Header.Set("Authorization", "Bearer mytoken")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if !called {
		t.Error("inner handler was not called for valid token")
	}
}

func TestGenerateToken(t *testing.T) {
	token, err := GenerateToken()
	if err != nil {
		t.Fatalf("GenerateToken() error = %v", err)
	}

	// Token should be hex-encoded 32 bytes = 64 hex chars.
	if len(token) != 64 {
		t.Errorf("token length = %d, want 64", len(token))
	}

	// Token should be valid hex.
	if _, err := hex.DecodeString(token); err != nil {
		t.Errorf("token is not valid hex: %v", err)
	}
}

func TestGenerateToken_Uniqueness(t *testing.T) {
	// Generate multiple tokens and ensure they are unique.
	tokens := make(map[string]struct{}, 10)
	for i := 0; i < 10; i++ {
		token, err := GenerateToken()
		if err != nil {
			t.Fatalf("GenerateToken() iteration %d error = %v", i, err)
		}
		if _, exists := tokens[token]; exists {
			t.Fatalf("duplicate token generated at iteration %d: %s", i, token)
		}
		tokens[token] = struct{}{}
	}
}
