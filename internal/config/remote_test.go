package config

import (
	"strings"
	"testing"
	"time"
)

func TestRemoteConfigValidate(t *testing.T) {
	cases := []struct {
		name    string
		rc      RemoteConfig
		wantErr string
	}{
		{
			name: "https accepted",
			rc:   RemoteConfig{URL: "https://config.example.com/v1/config"},
		},
		{
			name: "http loopback ip accepted",
			rc:   RemoteConfig{URL: "http://127.0.0.1:9100/v1/config"},
		},
		{
			name: "http localhost accepted",
			rc:   RemoteConfig{URL: "http://localhost:9100/v1/config"},
		},
		{
			name: "http ipv6 loopback accepted",
			rc:   RemoteConfig{URL: "http://[::1]:9100/v1/config"},
		},
		{
			name:    "http non-loopback rejected",
			rc:      RemoteConfig{URL: "http://config.example.com/v1/config"},
			wantErr: "plain http",
		},
		{
			name:    "other scheme rejected",
			rc:      RemoteConfig{URL: "ftp://config.example.com/v1/config"},
			wantErr: "scheme",
		},
		{
			name:    "missing host rejected",
			rc:      RemoteConfig{URL: "https:///v1/config"},
			wantErr: "missing host",
		},
		{
			name: "refresh interval parsed",
			rc:   RemoteConfig{URL: "https://config.example.com", RawRefreshInterval: "5m"},
		},
		{
			name: "refresh interval day shorthand",
			rc:   RemoteConfig{URL: "https://config.example.com", RawRefreshInterval: "1d"},
		},
		{
			name:    "refresh interval below floor",
			rc:      RemoteConfig{URL: "https://config.example.com", RawRefreshInterval: "10s"},
			wantErr: "1m minimum",
		},
		{
			name:    "refresh interval garbage",
			rc:      RemoteConfig{URL: "https://config.example.com", RawRefreshInterval: "soon"},
			wantErr: "refresh_interval",
		},
		{
			name:    "refresh interval validated even without url",
			rc:      RemoteConfig{RawRefreshInterval: "soon"},
			wantErr: "refresh_interval",
		},
		{
			name: "extra headers accepted",
			rc: RemoteConfig{
				URL:     "https://config.example.com",
				Headers: map[string]string{"X-Dotvault-Env": "production"},
			},
		},
		{
			name: "reserved header rejected case-insensitively",
			rc: RemoteConfig{
				URL:     "https://config.example.com",
				Headers: map[string]string{"x-dotvault-user": "someoneelse"},
			},
			wantErr: "built-in identity header",
		},
		{
			name: "header name with CR/LF rejected",
			rc: RemoteConfig{
				URL:     "https://config.example.com",
				Headers: map[string]string{"X-Bad\r\nHeader": "v"},
			},
			wantErr: "must not contain",
		},
		{
			name: "header value with NUL rejected",
			rc: RemoteConfig{
				URL:     "https://config.example.com",
				Headers: map[string]string{"X-Env": "a\x00b"},
			},
			wantErr: "must not contain",
		},
		{
			name: "empty section valid",
			rc:   RemoteConfig{},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.rc.validate()
			if tc.wantErr == "" {
				if err != nil {
					t.Fatalf("validate: %v", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("validate = %v, want error containing %q", err, tc.wantErr)
			}
		})
	}
}

func TestRemoteConfigRefreshIntervalSet(t *testing.T) {
	rc := RemoteConfig{URL: "https://config.example.com", RawRefreshInterval: "5m"}
	if err := rc.validate(); err != nil {
		t.Fatalf("validate: %v", err)
	}
	if rc.RefreshInterval != 5*time.Minute {
		t.Errorf("RefreshInterval = %v, want 5m", rc.RefreshInterval)
	}
}

// TestRemoteConfigRefreshIntervalNotAppliedWithoutURL pins that an interval
// in an otherwise-disabled section is validated (typos surface) but never
// applied — the overlay must not influence the daemon's refresh cadence
// while no URL is configured.
func TestRemoteConfigRefreshIntervalNotAppliedWithoutURL(t *testing.T) {
	rc := RemoteConfig{RawRefreshInterval: "5m"}
	if err := rc.validate(); err != nil {
		t.Fatalf("validate: %v", err)
	}
	if rc.RefreshInterval != 0 {
		t.Errorf("RefreshInterval = %v, want 0 when no URL is configured", rc.RefreshInterval)
	}
}

// TestRemoteConfigRefreshIntervalRecomputedOnRevalidate pins that
// RefreshInterval is derived state: re-validating a struct whose URL was
// cleared (or whose raw interval was emptied) drops the previously parsed
// value rather than letting it linger.
func TestRemoteConfigRefreshIntervalRecomputedOnRevalidate(t *testing.T) {
	rc := RemoteConfig{URL: "https://config.example.com", RawRefreshInterval: "5m"}
	if err := rc.validate(); err != nil {
		t.Fatalf("validate: %v", err)
	}
	if rc.RefreshInterval != 5*time.Minute {
		t.Fatalf("RefreshInterval = %v, want 5m", rc.RefreshInterval)
	}

	rc.URL = ""
	if err := rc.validate(); err != nil {
		t.Fatalf("revalidate without URL: %v", err)
	}
	if rc.RefreshInterval != 0 {
		t.Errorf("RefreshInterval = %v after URL cleared, want 0", rc.RefreshInterval)
	}

	rc.URL = "https://config.example.com"
	rc.RawRefreshInterval = ""
	if err := rc.validate(); err != nil {
		t.Fatalf("revalidate without raw interval: %v", err)
	}
	if rc.RefreshInterval != 0 {
		t.Errorf("RefreshInterval = %v after raw interval cleared, want 0", rc.RefreshInterval)
	}
}
