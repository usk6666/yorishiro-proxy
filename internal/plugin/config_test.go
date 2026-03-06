package plugin

import "testing"

func TestPluginConfig_Validate(t *testing.T) {
	tests := []struct {
		name    string
		config  PluginConfig
		wantErr bool
	}{
		{
			name: "valid config",
			config: PluginConfig{
				Path:     "test.star",
				Protocol: "http",
				Hooks:    []string{"on_receive_from_client"},
				OnError:  "skip",
			},
		},
		{
			name: "valid with abort",
			config: PluginConfig{
				Path:     "test.star",
				Protocol: "http",
				Hooks:    []string{"on_receive_from_client", "on_before_send_to_server"},
				OnError:  "abort",
			},
		},
		{
			name: "valid with default on_error",
			config: PluginConfig{
				Path:     "test.star",
				Protocol: "http",
				Hooks:    []string{"on_connect"},
			},
		},
		{
			name: "empty path",
			config: PluginConfig{
				Protocol: "http",
				Hooks:    []string{"on_connect"},
			},
			wantErr: true,
		},
		{
			name: "empty protocol",
			config: PluginConfig{
				Path:  "test.star",
				Hooks: []string{"on_connect"},
			},
			wantErr: true,
		},
		{
			name: "empty hooks",
			config: PluginConfig{
				Path:     "test.star",
				Protocol: "http",
			},
			wantErr: true,
		},
		{
			name: "invalid hook",
			config: PluginConfig{
				Path:     "test.star",
				Protocol: "http",
				Hooks:    []string{"invalid_hook"},
			},
			wantErr: true,
		},
		{
			name: "invalid on_error",
			config: PluginConfig{
				Path:     "test.star",
				Protocol: "http",
				Hooks:    []string{"on_connect"},
				OnError:  "invalid",
			},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.config.Validate()
			if (err != nil) != tt.wantErr {
				t.Errorf("PluginConfig.Validate() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}
