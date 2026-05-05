package config

import "os"

type Config struct {
	Port            string
	JWTSecret       string
	CoordinatorAddr string
	PolicyAddr      string
	Party1Addr      string
	Party2Addr      string
	Party3Addr      string
	NumParties      int
	WebAuthnRPID    string
	WebAuthnOrigin  string
}

func Load() *Config {
	return &Config{
		Port:            getEnv("PORT", "8080"),
		JWTSecret:       getEnv("JWT_SECRET", "dev-secret-change-in-production"),
		CoordinatorAddr: getEnv("COORDINATOR_ADDR", "localhost:50051"),
		PolicyAddr:      getEnv("POLICY_ADDR", "localhost:50052"),
		Party1Addr:      getEnv("PARTY_1_ADDR", "localhost:50060"),
		Party2Addr:      getEnv("PARTY_2_ADDR", "localhost:50061"),
		Party3Addr:      getEnv("PARTY_3_ADDR", "localhost:50062"),
		NumParties:      3,
		WebAuthnRPID:    getEnv("WEBAUTHN_RP_ID", "localhost"),
		WebAuthnOrigin:  getEnv("WEBAUTHN_ORIGIN", "http://localhost:5173"),
	}
}

func getEnv(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}
