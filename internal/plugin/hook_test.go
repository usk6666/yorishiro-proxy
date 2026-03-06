package plugin

import "testing"

func TestValidateHook(t *testing.T) {
	tests := []struct {
		name    string
		hook    Hook
		wantErr bool
	}{
		{name: "on_receive_from_client", hook: HookOnReceiveFromClient},
		{name: "on_before_send_to_server", hook: HookOnBeforeSendToServer},
		{name: "on_receive_from_server", hook: HookOnReceiveFromServer},
		{name: "on_before_send_to_client", hook: HookOnBeforeSendToClient},
		{name: "on_connect", hook: HookOnConnect},
		{name: "on_tls_handshake", hook: HookOnTLSHandshake},
		{name: "on_disconnect", hook: HookOnDisconnect},
		{name: "unknown hook", hook: Hook("unknown"), wantErr: true},
		{name: "empty hook", hook: Hook(""), wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateHook(tt.hook)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidateHook(%q) error = %v, wantErr %v", tt.hook, err, tt.wantErr)
			}
		})
	}
}

func TestValidateAction(t *testing.T) {
	tests := []struct {
		name    string
		hook    Hook
		action  ActionType
		wantErr bool
	}{
		{name: "CONTINUE in any hook", hook: HookOnBeforeSendToServer, action: ActionContinue},
		{name: "DROP in on_receive_from_client", hook: HookOnReceiveFromClient, action: ActionDrop},
		{name: "RESPOND in on_receive_from_client", hook: HookOnReceiveFromClient, action: ActionRespond},
		{name: "DROP in on_before_send_to_server", hook: HookOnBeforeSendToServer, action: ActionDrop, wantErr: true},
		{name: "RESPOND in on_connect", hook: HookOnConnect, action: ActionRespond, wantErr: true},
		{name: "DROP in on_disconnect", hook: HookOnDisconnect, action: ActionDrop, wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateAction(tt.hook, tt.action)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidateAction(%q, %v) error = %v, wantErr %v", tt.hook, tt.action, err, tt.wantErr)
			}
		})
	}
}
