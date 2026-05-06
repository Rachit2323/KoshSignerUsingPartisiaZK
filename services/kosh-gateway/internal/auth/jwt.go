package auth

import (
	"net/http"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

type Claims struct {
	APIKey string `json:"api_key"`
	jwt.RegisteredClaims
}

// Middleware validates Bearer JWT on every request.
// Skips /api/v1/health (public) and /api/v1/token (token issuance).
func Middleware(secret string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Public endpoints (no JWT required)
			pub := map[string]bool{
				"/api/v1/health":                     true,
				"/api/v1/token":                      true,
				"/api/v1/passkeys/register/start":    true,
				"/api/v1/passkeys/register/finish":   true,
				"/api/v1/passkeys/auth/start":        true,
				"/api/v1/passkeys/auth/finish":       true,
				"/api/v1/passkeys/me":                true,
				"/api/v1/passkeys/select-key":        true,
				"/api/v1/passkeys/link-key":          true,
				"/api/v1/passkeys/create-key":        true,
				"/api/v1/passkeys/reuse-sign":        true,
				"/api/v1/runtime/preflight":          true,
				"/api/v1/runtime/active":             true,
				"/api/v1/threshold/key-status":       true,
				"/api/v1/threshold/task-signature":   true,
				"/api/v1/evm/build-eth-transfer":     true,
				"/api/v1/evm/broadcast-signed":       true,
			}
			if pub[r.URL.Path] {
				next.ServeHTTP(w, r)
				return
			}
			// job polling also public
			if len(r.URL.Path) > len("/api/v1/jobs/") && r.URL.Path[:len("/api/v1/jobs/")] == "/api/v1/jobs/" {
				next.ServeHTTP(w, r)
				return
			}

			authHeader := r.Header.Get("Authorization")
			if !strings.HasPrefix(authHeader, "Bearer ") {
				http.Error(w, `{"error":"missing Authorization header"}`, http.StatusUnauthorized)
				return
			}
			tokenStr := strings.TrimPrefix(authHeader, "Bearer ")

			claims := &Claims{}
			tok, err := jwt.ParseWithClaims(tokenStr, claims, func(t *jwt.Token) (interface{}, error) {
				if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
					return nil, jwt.ErrSignatureInvalid
				}
				return []byte(secret), nil
			})
			if err != nil || !tok.Valid {
				http.Error(w, `{"error":"invalid or expired token"}`, http.StatusUnauthorized)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

// IssueToken returns a signed JWT valid for 24h (used by /api/v1/token).
func IssueToken(secret, apiKey string) (string, error) {
	claims := &Claims{
		APIKey: apiKey,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(24 * time.Hour)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
		},
	}
	tok := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return tok.SignedString([]byte(secret))
}
