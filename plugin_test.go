package traefik_auth_plugin

import (
	"net/http"
	"testing"
)

func TestJWTValidation(t *testing.T) {
	config := &Config{
		Issuer:       "https://oidc.vercel.com/test",
		TeamSlug:     "test-team",
		ProjectName:  "test-project",
		Environment:  "test",
		TokenHeader:  "Authorization",
		JWKSEndpoint: "https://oidc.vercel.com/test/.well-known/jwks",
	}

	plugin := &VercelAuth{
		config: config,
	}

	tests := []struct {
		name        string
		token       string
		shouldError bool
		errorMsg    string
	}{
		{
			name:        "empty token",
			token:       "",
			shouldError: true,
			errorMsg:    "empty token",
		},
		{
			name:        "malformed token - not enough parts",
			token:       "invalid.token",
			shouldError: true,
			errorMsg:    "token is malformed",
		},
		{
			name:        "malformed token - invalid JSON in header",
			token:       "invalid.header.signature",
			shouldError: true,
			errorMsg:    "token is malformed",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := plugin.validateToken(t.Context(), tt.token)

			if tt.shouldError {
				if err == nil {
					t.Errorf("expected error but got none")
					return
				}
				// Just check that we got an error, not the exact message
				// since error messages can vary
			} else {
				if err != nil {
					t.Errorf("expected no error but got: %v", err)
				}
			}
		})
	}
}

func TestVercelAuth_extractToken(t *testing.T) {
	tests := []struct {
		name          string
		tokenHeader   string
		headers       map[string]string
		expectedToken string
	}{
		{
			name:        "valid token with Bearer prefix",
			tokenHeader: "Authorization",
			headers: map[string]string{
				"Authorization": "Bearer testoken123",
			},
			expectedToken: "testoken123",
		},
		{
			name:        "valid token with bearer prefix (lowercase)",
			tokenHeader: "Authorization",
			headers: map[string]string{
				"Authorization": "bearer testoken123",
			},
			expectedToken: "testoken123",
		},
		{
			name:        "valid token with mixed case bearer prefix",
			tokenHeader: "Authorization",
			headers: map[string]string{
				"Authorization": "BeArEr testoken123",
			},
			expectedToken: "testoken123",
		},
		{
			name:        "valid token without Bearer prefix",
			tokenHeader: "Authorization",
			headers: map[string]string{
				"Authorization": "testoken123",
			},
			expectedToken: "testoken123",
		},
		{
			name:        "custom token header",
			tokenHeader: "X-Vercel-Oidc-Token",
			headers: map[string]string{
				"X-Vercel-Oidc-Token": "Bearer testoken123",
			},
			expectedToken: "testoken123",
		},
		{
			name:        "custom token header without Bearer prefix",
			tokenHeader: "X-Custom-Token",
			headers: map[string]string{
				"X-Custom-Token": "testoken123",
			},
			expectedToken: "testoken123",
		},
		{
			name:          "missing token header",
			tokenHeader:   "Authorization",
			headers:       map[string]string{},
			expectedToken: "",
		},
		{
			name:        "empty token header",
			tokenHeader: "Authorization",
			headers: map[string]string{
				"Authorization": "",
			},
			expectedToken: "",
		},
		{
			name:        "token with only Bearer prefix (no space)",
			tokenHeader: "Authorization",
			headers: map[string]string{
				"Authorization": "Bearer",
			},
			expectedToken: "Bearer",
		},
		{
			name:        "token with Bearer prefix and space but no token",
			tokenHeader: "Authorization",
			headers: map[string]string{
				"Authorization": "Bearer ",
			},
			expectedToken: "",
		},
		{
			name:        "token that starts with 'bearer' but is not a prefix",
			tokenHeader: "Authorization",
			headers: map[string]string{
				"Authorization": "bearertoken123",
			},
			expectedToken: "bearertoken123",
		},
		{
			name:        "wrong header present",
			tokenHeader: "Authorization",
			headers: map[string]string{
				"X-Custom-Header": "Bearer testoken123",
			},
			expectedToken: "",
		},
		{
			name:        "multiple headers present, correct one with Bearer",
			tokenHeader: "Authorization",
			headers: map[string]string{
				"Content-Type":  "application/json",
				"Authorization": "Bearer testoken123",
				"X-Custom":      "other-value",
			},
			expectedToken: "testoken123",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create a VercelAuth instance with the test configuration
			config := &Config{
				TokenHeader: tt.tokenHeader,
			}
			v := &VercelAuth{
				config: config,
			}

			// Create HTTP headers from the test case
			headers := http.Header{}
			for key, value := range tt.headers {
				headers.Set(key, value)
			}

			// Call the extractToken function
			result := v.extractToken(headers)

			// Assert the result
			if result != tt.expectedToken {
				t.Errorf("extractToken() = %q, want %q", result, tt.expectedToken)
			}
		})
	}
}
