package main

import "testing"

func TestIsGUIBinary(t *testing.T) {
	tests := []struct {
		arg0 string
		want bool
	}{
		{"dotvault", false},
		{"./dotvault", false},
		{"/usr/local/bin/dotvault", false},
		{"dotvault.exe", false},
		{`C:\Program Files\dotvault\dotvault.exe`, false},
		{"dotvaultw", true},
		{"dotvaultw.exe", true},
		{"DotVaultW.exe", true},
		{`C:\Program Files\dotvault\dotvaultw.exe`, true},
		{"./dotvaultw", true},
		{"dotvault-windows-amd64.exe", false},
		{"dotvaultw-windows-amd64.exe", false},
		{"", false},
	}
	for _, tc := range tests {
		t.Run(tc.arg0, func(t *testing.T) {
			if got := isGUIBinary(tc.arg0); got != tc.want {
				t.Errorf("isGUIBinary(%q) = %v, want %v", tc.arg0, got, tc.want)
			}
		})
	}
}
