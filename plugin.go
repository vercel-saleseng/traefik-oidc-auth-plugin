package traefik_auth_plugin

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/lestrrat-go/jwx/v3/jwk"
	"github.com/lestrrat-go/jwx/v3/jwt"
)

// VercelAuth is the plugin struct.
type VercelAuth struct {
	next   http.Handler
	name   string
	config *Config
	jwkSet jwk.Set
	client *http.Client
}

// New creates a new VercelAuth plugin instance.
func New(ctx context.Context, next http.Handler, config *Config, name string) (http.Handler, error) {
	// Validate the config
	err := config.Validate()
	if err != nil {
		return nil, fmt.Errorf("configuration error: %w", err)
	}

	plugin := &VercelAuth{
		next:   next,
		name:   name,
		config: config,
		client: &http.Client{
			Timeout: 30 * time.Second,
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{
					MinVersion: tls.VersionTLS12,
				},
			},
		},
	}

	// Fetch JWKS on initialization
	err = plugin.refreshJWKS(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch JWKS: %w", err)
	}

	return plugin, nil
}

// ServeHTTP implements the middleware logic.
func (v *VercelAuth) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	token := v.extractToken(r.Header)
	if token == "" {
		v.unauthorized(w, "Missing token")
		return
	}

	err := v.validateToken(r.Context(), token)
	if err != nil {
		v.unauthorized(w, "Invalid token: "+err.Error())
		return
	}

	v.next.ServeHTTP(w, r)
}

// extractToken extracts the JWT token from the request.
func (v *VercelAuth) extractToken(h http.Header) string {
	token := h.Get(v.config.TokenHeader)
	if token == "" {
		return ""
	}

	// Trim the Bearer prefix (case-insensitive) if found
	const (
		bearerPrefix = "bearer "
		prefixLen    = len(bearerPrefix)
	)
	if len(token) >= prefixLen && strings.ToLower(token[:prefixLen]) == bearerPrefix {
		return token[prefixLen:]
	}

	return token
}

// validateToken validates the JWT token.
func (v *VercelAuth) validateToken(ctx context.Context, tokenString string) error {
	// Parse and verify the token
	token, err := jwt.Parse([]byte(tokenString),
		jwt.WithContext(ctx),
		jwt.WithKeySet(v.jwkSet),
		jwt.WithIssuer(v.config.Issuer),
		jwt.WithAudience(v.config.Audience()),
		jwt.WithSubject(v.config.Subject()),
		jwt.WithValidate(true),
	)
	if err != nil {
		return fmt.Errorf("failed to verify token: %w", err)
	}

	j, _ := json.Marshal(token)
	fmt.Println("AAAA", string(j))

	return nil
}

// refreshJWKS fetches the JWKS from the configured endpoint.
func (v *VercelAuth) refreshJWKS(ctx context.Context) error {
	resp, err := v.client.Get(v.config.JWKSEndpoint)
	if err != nil {
		return fmt.Errorf("failed to fetch JWKS: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("JWKS endpoint returned status %d", resp.StatusCode)
	}

	jwkSet, err := jwk.ParseReader(resp.Body)
	if err != nil {
		return fmt.Errorf("failed to parse JWKS: %w", err)
	}

	v.jwkSet = jwkSet
	return nil
}

// unauthorized sends an unauthorized response.
func (v *VercelAuth) unauthorized(w http.ResponseWriter, message string) {
	w.Header().Set("Content-Type", "text/plain; charset=UTF-8")
	w.WriteHeader(http.StatusUnauthorized)

	// Ignore errors here, headers already sent
	_, _ = fmt.Fprint(w, message)
}
