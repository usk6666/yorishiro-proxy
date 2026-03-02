package selfupdate

import "testing"

func TestParseSemver(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		want    semver
		wantErr bool
	}{
		{
			name:  "simple version",
			input: "v1.2.3",
			want:  semver{Major: 1, Minor: 2, Patch: 3},
		},
		{
			name:  "without v prefix",
			input: "1.2.3",
			want:  semver{Major: 1, Minor: 2, Patch: 3},
		},
		{
			name:  "with prerelease",
			input: "v1.0.0-rc.1",
			want:  semver{Major: 1, Minor: 0, Patch: 0, Prerelease: "rc.1"},
		},
		{
			name:  "with alpha prerelease",
			input: "v2.1.0-alpha.3",
			want:  semver{Major: 2, Minor: 1, Patch: 0, Prerelease: "alpha.3"},
		},
		{
			name:  "zero version",
			input: "v0.0.0",
			want:  semver{Major: 0, Minor: 0, Patch: 0},
		},
		{
			name:  "large numbers",
			input: "v100.200.300",
			want:  semver{Major: 100, Minor: 200, Patch: 300},
		},
		{
			name:    "empty string",
			input:   "",
			wantErr: true,
		},
		{
			name:    "only v prefix",
			input:   "v",
			wantErr: true,
		},
		{
			name:    "two parts",
			input:   "v1.2",
			wantErr: true,
		},
		{
			name:    "four parts",
			input:   "v1.2.3.4",
			wantErr: true,
		},
		{
			name:    "non-numeric major",
			input:   "vX.2.3",
			wantErr: true,
		},
		{
			name:    "non-numeric minor",
			input:   "v1.Y.3",
			wantErr: true,
		},
		{
			name:    "non-numeric patch",
			input:   "v1.2.Z",
			wantErr: true,
		},
		{
			name:    "just text",
			input:   "dev",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := parseSemver(tt.input)
			if (err != nil) != tt.wantErr {
				t.Errorf("parseSemver(%q) error = %v, wantErr %v", tt.input, err, tt.wantErr)
				return
			}
			if !tt.wantErr && got != tt.want {
				t.Errorf("parseSemver(%q) = %v, want %v", tt.input, got, tt.want)
			}
		})
	}
}

func TestSemver_String(t *testing.T) {
	tests := []struct {
		name  string
		input semver
		want  string
	}{
		{
			name:  "simple version",
			input: semver{Major: 1, Minor: 2, Patch: 3},
			want:  "1.2.3",
		},
		{
			name:  "with prerelease",
			input: semver{Major: 1, Minor: 0, Patch: 0, Prerelease: "rc.1"},
			want:  "1.0.0-rc.1",
		},
		{
			name:  "zero version",
			input: semver{},
			want:  "0.0.0",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.input.String()
			if got != tt.want {
				t.Errorf("semver.String() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestCompareSemver(t *testing.T) {
	tests := []struct {
		name string
		a    semver
		b    semver
		want int
	}{
		{
			name: "equal",
			a:    semver{Major: 1, Minor: 2, Patch: 3},
			b:    semver{Major: 1, Minor: 2, Patch: 3},
			want: 0,
		},
		{
			name: "major greater",
			a:    semver{Major: 2, Minor: 0, Patch: 0},
			b:    semver{Major: 1, Minor: 9, Patch: 9},
			want: 1,
		},
		{
			name: "major less",
			a:    semver{Major: 1, Minor: 0, Patch: 0},
			b:    semver{Major: 2, Minor: 0, Patch: 0},
			want: -1,
		},
		{
			name: "minor greater",
			a:    semver{Major: 1, Minor: 3, Patch: 0},
			b:    semver{Major: 1, Minor: 2, Patch: 9},
			want: 1,
		},
		{
			name: "minor less",
			a:    semver{Major: 1, Minor: 2, Patch: 0},
			b:    semver{Major: 1, Minor: 3, Patch: 0},
			want: -1,
		},
		{
			name: "patch greater",
			a:    semver{Major: 1, Minor: 2, Patch: 4},
			b:    semver{Major: 1, Minor: 2, Patch: 3},
			want: 1,
		},
		{
			name: "patch less",
			a:    semver{Major: 1, Minor: 2, Patch: 3},
			b:    semver{Major: 1, Minor: 2, Patch: 4},
			want: -1,
		},
		{
			name: "release beats prerelease",
			a:    semver{Major: 1, Minor: 0, Patch: 0},
			b:    semver{Major: 1, Minor: 0, Patch: 0, Prerelease: "rc.1"},
			want: 1,
		},
		{
			name: "prerelease loses to release",
			a:    semver{Major: 1, Minor: 0, Patch: 0, Prerelease: "rc.1"},
			b:    semver{Major: 1, Minor: 0, Patch: 0},
			want: -1,
		},
		{
			name: "prerelease lexicographic comparison",
			a:    semver{Major: 1, Minor: 0, Patch: 0, Prerelease: "rc.2"},
			b:    semver{Major: 1, Minor: 0, Patch: 0, Prerelease: "rc.1"},
			want: 1,
		},
		{
			name: "alpha before beta",
			a:    semver{Major: 1, Minor: 0, Patch: 0, Prerelease: "alpha"},
			b:    semver{Major: 1, Minor: 0, Patch: 0, Prerelease: "beta"},
			want: -1,
		},
		{
			name: "both prerelease equal",
			a:    semver{Major: 1, Minor: 0, Patch: 0, Prerelease: "rc.1"},
			b:    semver{Major: 1, Minor: 0, Patch: 0, Prerelease: "rc.1"},
			want: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := compareSemver(tt.a, tt.b)
			if got != tt.want {
				t.Errorf("compareSemver(%v, %v) = %d, want %d", tt.a, tt.b, got, tt.want)
			}
		})
	}
}

func TestIsNewerThan(t *testing.T) {
	tests := []struct {
		name    string
		latest  string
		current string
		want    bool
		wantErr bool
	}{
		{
			name:    "newer version available",
			latest:  "v1.1.0",
			current: "v1.0.0",
			want:    true,
		},
		{
			name:    "same version",
			latest:  "v1.0.0",
			current: "v1.0.0",
			want:    false,
		},
		{
			name:    "older version on remote",
			latest:  "v1.0.0",
			current: "v1.1.0",
			want:    false,
		},
		{
			name:    "dev build treats any release as newer",
			latest:  "v0.1.0",
			current: "dev",
			want:    true,
		},
		{
			name:    "prerelease is newer than older release",
			latest:  "v2.0.0-rc.1",
			current: "v1.0.0",
			want:    true,
		},
		{
			name:    "release is newer than same version prerelease",
			latest:  "v1.0.0",
			current: "v1.0.0-rc.1",
			want:    true,
		},
		{
			name:    "invalid latest version",
			latest:  "not-a-version",
			current: "v1.0.0",
			wantErr: true,
		},
		{
			name:    "invalid current version",
			latest:  "v1.0.0",
			current: "not-a-version",
			wantErr: true,
		},
		{
			name:    "dev build with invalid latest",
			latest:  "not-a-version",
			current: "dev",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := IsNewerThan(tt.latest, tt.current)
			if (err != nil) != tt.wantErr {
				t.Errorf("IsNewerThan(%q, %q) error = %v, wantErr %v", tt.latest, tt.current, err, tt.wantErr)
				return
			}
			if !tt.wantErr && got != tt.want {
				t.Errorf("IsNewerThan(%q, %q) = %v, want %v", tt.latest, tt.current, got, tt.want)
			}
		})
	}
}
