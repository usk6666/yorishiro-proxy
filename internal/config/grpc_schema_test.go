package config

import (
	"strings"
	"testing"
)

func TestGRPCSchemaConfig_Validate(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name    string
		input   *GRPCSchemaConfig
		wantErr string // substring match; "" = expect no error
	}{
		{"nil receiver", nil, ""},
		{"empty struct (use default)", &GRPCSchemaConfig{}, ""},
		{"explicit path", &GRPCSchemaConfig{ProtocBinary: "/opt/protoc/bin/protoc"}, ""},
		{"bare name", &GRPCSchemaConfig{ProtocBinary: "protoc"}, ""},
		{"all-whitespace rejected", &GRPCSchemaConfig{ProtocBinary: "   "}, "whitespace-only"},
		{"tab-only rejected", &GRPCSchemaConfig{ProtocBinary: "\t"}, "whitespace-only"},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			err := tc.input.Validate()
			if tc.wantErr == "" {
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
				return
			}
			if err == nil {
				t.Fatalf("want error containing %q, got nil", tc.wantErr)
			}
			if !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("err = %q, want substring %q", err.Error(), tc.wantErr)
			}
		})
	}
}

func TestResolveProtocBinary_Precedence(t *testing.T) {
	// Cannot t.Parallel — sub-tests mutate the process env.

	t.Run("default when nothing set", func(t *testing.T) {
		t.Setenv(ProtocBinaryEnvVar, "")
		if got := ResolveProtocBinary(nil); got != DefaultProtocBinary {
			t.Errorf("got %q, want %q", got, DefaultProtocBinary)
		}
	})

	t.Run("config overrides default", func(t *testing.T) {
		t.Setenv(ProtocBinaryEnvVar, "")
		cfg := &ProxyConfig{GRPCSchema: &GRPCSchemaConfig{ProtocBinary: "/opt/protoc"}}
		if got := ResolveProtocBinary(cfg); got != "/opt/protoc" {
			t.Errorf("got %q, want /opt/protoc", got)
		}
	})

	t.Run("env var overrides config", func(t *testing.T) {
		t.Setenv(ProtocBinaryEnvVar, "/env/protoc")
		cfg := &ProxyConfig{GRPCSchema: &GRPCSchemaConfig{ProtocBinary: "/opt/protoc"}}
		if got := ResolveProtocBinary(cfg); got != "/env/protoc" {
			t.Errorf("got %q, want /env/protoc", got)
		}
	})

	t.Run("empty env var falls through to config", func(t *testing.T) {
		t.Setenv(ProtocBinaryEnvVar, "")
		cfg := &ProxyConfig{GRPCSchema: &GRPCSchemaConfig{ProtocBinary: "/opt/protoc"}}
		if got := ResolveProtocBinary(cfg); got != "/opt/protoc" {
			t.Errorf("got %q, want /opt/protoc", got)
		}
	})

	t.Run("whitespace env var falls through to config", func(t *testing.T) {
		t.Setenv(ProtocBinaryEnvVar, "   ")
		cfg := &ProxyConfig{GRPCSchema: &GRPCSchemaConfig{ProtocBinary: "/opt/protoc"}}
		if got := ResolveProtocBinary(cfg); got != "/opt/protoc" {
			t.Errorf("got %q, want /opt/protoc", got)
		}
	})

	t.Run("whitespace config falls through to default", func(t *testing.T) {
		t.Setenv(ProtocBinaryEnvVar, "")
		cfg := &ProxyConfig{GRPCSchema: &GRPCSchemaConfig{ProtocBinary: "  "}}
		if got := ResolveProtocBinary(cfg); got != DefaultProtocBinary {
			t.Errorf("got %q, want %q", got, DefaultProtocBinary)
		}
	})

	t.Run("nil GRPCSchema substruct uses default", func(t *testing.T) {
		t.Setenv(ProtocBinaryEnvVar, "")
		cfg := &ProxyConfig{}
		if got := ResolveProtocBinary(cfg); got != DefaultProtocBinary {
			t.Errorf("got %q, want %q", got, DefaultProtocBinary)
		}
	})
}

func TestProxyConfig_Validate_GRPCSchema(t *testing.T) {
	t.Parallel()
	c := &ProxyConfig{
		GRPCSchema: &GRPCSchemaConfig{ProtocBinary: "\t"},
	}
	err := c.Validate()
	if err == nil || !strings.Contains(err.Error(), "whitespace-only") {
		t.Fatalf("want whitespace-only error, got %v", err)
	}
}
