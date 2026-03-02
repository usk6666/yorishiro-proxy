package main

import "testing"

func TestBuildVersion_Default(t *testing.T) {
	// Save and restore original values.
	origVersion, origCommit, origDate := version, commit, date
	t.Cleanup(func() {
		version, commit, date = origVersion, origCommit, origDate
	})

	version = "dev"
	commit = "unknown"
	date = "unknown"

	got := buildVersion()
	if got != "dev" {
		t.Errorf("buildVersion() = %q, want %q", got, "dev")
	}
}

func TestBuildVersion_Release(t *testing.T) {
	origVersion, origCommit, origDate := version, commit, date
	t.Cleanup(func() {
		version, commit, date = origVersion, origCommit, origDate
	})

	tests := []struct {
		name    string
		version string
		commit  string
		date    string
		want    string
	}{
		{
			name:    "standard release",
			version: "v1.0.0",
			commit:  "abc1234",
			date:    "2026-01-01T00:00:00Z",
			want:    "v1.0.0 (abc1234 2026-01-01T00:00:00Z)",
		},
		{
			name:    "prerelease",
			version: "v1.0.0-rc.1",
			commit:  "def5678",
			date:    "2026-03-01T12:00:00Z",
			want:    "v1.0.0-rc.1 (def5678 2026-03-01T12:00:00Z)",
		},
		{
			name:    "dev version returns dev only",
			version: "dev",
			commit:  "abc1234",
			date:    "2026-01-01T00:00:00Z",
			want:    "dev",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			version = tt.version
			commit = tt.commit
			date = tt.date

			got := buildVersion()
			if got != tt.want {
				t.Errorf("buildVersion() = %q, want %q", got, tt.want)
			}
		})
	}
}
