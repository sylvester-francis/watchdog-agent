package main

// Brand variables — set at build time via ldflags to customize display
// names, config paths, and environment variable prefixes.
//
// Default build:
//
//	go build -o watchdog-agent .
//
// Custom brand:
//
//	go build -ldflags "-X main.BrandName=MyBrand -X main.BrandAgent=mybrand-agent -X main.BrandEnvPrefix=MYBRAND" -o mybrand-agent .
var (
	BrandName      = "WatchDog"       // Display name (e.g. "WatchDog Agent starting")
	BrandAgent     = "watchdog-agent" // Binary/service name (e.g. /etc/watchdog-agent/)
	BrandEnvPrefix = "WATCHDOG"       // Env var prefix (e.g. WATCHDOG_API_KEY)

	// ReleaseSigningPublicKey is the hex-encoded ed25519 public key used to
	// verify update binary signatures. Override at build time via:
	//   -ldflags "-X main.ReleaseSigningPublicKey=<hex>"
	// When set to all zeros (placeholder), signature verification is skipped.
	ReleaseSigningPublicKey = "0000000000000000000000000000000000000000000000000000000000000000"
)

// BrandConfigDir returns the default config directory path.
func BrandConfigDir() string {
	return "/etc/" + BrandAgent
}

// BrandDefaultKeyFile returns the default API key file path.
func BrandDefaultKeyFile() string {
	return BrandConfigDir() + "/api-key"
}

// BrandEnvAPIKey returns the environment variable name for the API key.
func BrandEnvAPIKey() string {
	return BrandEnvPrefix + "_API_KEY"
}

// BrandUserAgent returns the User-Agent header value.
func BrandUserAgent() string {
	return BrandName + "-Agent/1.0"
}
