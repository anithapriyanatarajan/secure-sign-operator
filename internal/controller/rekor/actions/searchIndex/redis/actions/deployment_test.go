package actions

import (
	"strings"
	"testing"

	configv1 "github.com/openshift/api/config/v1"
	rhtasv1 "github.com/securesign/operator/api/v1"
	appconfig "github.com/securesign/operator/internal/config"
	v1 "k8s.io/api/apps/v1"
	core "k8s.io/api/core/v1"
)

func TestRedisTLSProtocols(t *testing.T) {
	tests := []struct {
		name string
		min  configv1.TLSProtocolVersion
		want string
	}{
		{"TLS 1.0 floor", configv1.VersionTLS10, "TLSv1 TLSv1.1 TLSv1.2 TLSv1.3"},
		{"TLS 1.1 floor", configv1.VersionTLS11, "TLSv1.1 TLSv1.2 TLSv1.3"},
		{"TLS 1.2 floor", configv1.VersionTLS12, "TLSv1.2 TLSv1.3"},
		{"TLS 1.3 floor", configv1.VersionTLS13, "TLSv1.3"},
		{"unset falls back to Redis default", configv1.TLSProtocolVersion(""), ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := redisTLSProtocols(tt.min); got != tt.want {
				t.Errorf("redisTLSProtocols(%q) = %q, want %q", tt.min, got, tt.want)
			}
		})
	}
}

func TestRedisTLSCiphers(t *testing.T) {
	tests := []struct {
		name      string
		ciphers   []string
		wantTLS12 string
		wantTLS13 string
	}{
		{
			name:      "nil profile omits both directives",
			ciphers:   nil,
			wantTLS12: "",
			wantTLS13: "",
		},
		{
			name:      "TLS 1.3 only ciphers go to tls-ciphersuites",
			ciphers:   []string{"TLS_AES_128_GCM_SHA256", "TLS_AES_256_GCM_SHA384"},
			wantTLS12: "",
			wantTLS13: "TLS_AES_128_GCM_SHA256:TLS_AES_256_GCM_SHA384",
		},
		{
			name:      "OpenSSL 1.2 ciphers go to tls-ciphers",
			ciphers:   []string{"ECDHE-ECDSA-AES128-GCM-SHA256", "ECDHE-RSA-AES128-GCM-SHA256"},
			wantTLS12: "ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256",
			wantTLS13: "",
		},
		{
			name: "mixed profile splits by TLS_ prefix preserving order",
			ciphers: []string{
				"TLS_AES_128_GCM_SHA256",
				"ECDHE-ECDSA-AES128-GCM-SHA256",
				"TLS_CHACHA20_POLY1305_SHA256",
				"ECDHE-RSA-AES256-GCM-SHA384",
			},
			wantTLS12: "ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES256-GCM-SHA384",
			wantTLS13: "TLS_AES_128_GCM_SHA256:TLS_CHACHA20_POLY1305_SHA256",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotTLS12, gotTLS13 := redisTLSCiphers(tt.ciphers)
			if gotTLS12 != tt.wantTLS12 {
				t.Errorf("redisTLSCiphers() tls12 = %q, want %q", gotTLS12, tt.wantTLS12)
			}
			if gotTLS13 != tt.wantTLS13 {
				t.Errorf("redisTLSCiphers() tls13 = %q, want %q", gotTLS13, tt.wantTLS13)
			}
		})
	}
}

// redisConfLines renders the deployment via ensureTLS and returns the redis.conf lines
// the enable-tls init container appends. It exercises the real rendering path end to end.
func redisConfLines(t *testing.T) []string {
	t.Helper()

	tlsCfg := rhtasv1.TLS{
		CertRef:       &rhtasv1.SecretKeySelector{LocalObjectReference: rhtasv1.LocalObjectReference{Name: "redis-tls"}, Key: "tls.crt"},
		PrivateKeyRef: &rhtasv1.SecretKeySelector{LocalObjectReference: rhtasv1.LocalObjectReference{Name: "redis-tls"}, Key: "tls.key"},
	}

	dp := &v1.Deployment{}
	if err := (deployAction{}).ensureTLS(tlsCfg, "/etc/ssl/ca.crt")(dp); err != nil {
		t.Fatalf("ensureTLS returned error: %v", err)
	}

	var init *core.Container
	for i := range dp.Spec.Template.Spec.InitContainers {
		if dp.Spec.Template.Spec.InitContainers[i].Name == "enable-tls" {
			init = &dp.Spec.Template.Spec.InitContainers[i]
			break
		}
	}
	if init == nil || len(init.Args) == 0 {
		t.Fatal("enable-tls init container or its args not found")
	}
	return strings.Split(init.Args[0], "\n")
}

func hasLineContaining(lines []string, substr string) bool {
	for _, l := range lines {
		if strings.Contains(l, substr) {
			return true
		}
	}
	return false
}

// TestEnsureTLSRendersProfile drives the full ensureTLS render path and asserts the
// resolved cluster profile is written into redis.conf as tls-protocols/tls-ciphers/
// tls-ciphersuites directives.
func TestEnsureTLSRendersProfile(t *testing.T) {
	saved := appconfig.ClusterTLSProfile
	t.Cleanup(func() { appconfig.ClusterTLSProfile = saved })

	appconfig.ClusterTLSProfile = configv1.TLSProfileSpec{
		MinTLSVersion: configv1.VersionTLS12,
		Ciphers: []string{
			"TLS_AES_128_GCM_SHA256",
			"ECDHE-ECDSA-AES128-GCM-SHA256",
			"ECDHE-RSA-AES256-GCM-SHA384",
		},
	}

	lines := redisConfLines(t)

	// Base directives are always present.
	if !hasLineContaining(lines, "tls-port") {
		t.Error("expected tls-port directive in redis.conf")
	}
	if !hasLineContaining(lines, `tls-protocols "TLSv1.2 TLSv1.3"`) {
		t.Errorf("expected tls-protocols floor line, got: %v", lines)
	}
	if !hasLineContaining(lines, `tls-ciphers "ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES256-GCM-SHA384"`) {
		t.Errorf("expected tls-ciphers line with 1.2 ciphers, got: %v", lines)
	}
	if !hasLineContaining(lines, `tls-ciphersuites "TLS_AES_128_GCM_SHA256"`) {
		t.Errorf("expected tls-ciphersuites line with 1.3 cipher, got: %v", lines)
	}
}

// TestEnsureTLSEmptyProfileNoOp confirms that with no resolved profile (vanilla k8s or
// disabled), no TLS profile directives are added and Redis keeps its built-in defaults.
func TestEnsureTLSEmptyProfileNoOp(t *testing.T) {
	saved := appconfig.ClusterTLSProfile
	t.Cleanup(func() { appconfig.ClusterTLSProfile = saved })

	appconfig.ClusterTLSProfile = configv1.TLSProfileSpec{}

	lines := redisConfLines(t)

	// Base TLS wiring stays; profile-derived directives must be absent.
	if !hasLineContaining(lines, "tls-port") {
		t.Error("expected base tls-port directive even with empty profile")
	}
	for _, directive := range []string{"tls-protocols", "tls-ciphers", "tls-ciphersuites"} {
		if hasLineContaining(lines, directive) {
			t.Errorf("did not expect %q directive with empty profile, got: %v", directive, lines)
		}
	}
}
