package plugin

import "testing"

func TestActionType_String(t *testing.T) {
	tests := []struct {
		name   string
		action ActionType
		want   string
	}{
		{name: "CONTINUE", action: ActionContinue, want: "CONTINUE"},
		{name: "DROP", action: ActionDrop, want: "DROP"},
		{name: "RESPOND", action: ActionRespond, want: "RESPOND"},
		{name: "unknown", action: ActionType(99), want: "ActionType(99)"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.action.String(); got != tt.want {
				t.Errorf("ActionType.String() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestParseActionType(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		want    ActionType
		wantErr bool
	}{
		{name: "CONTINUE", input: "CONTINUE", want: ActionContinue},
		{name: "DROP", input: "DROP", want: ActionDrop},
		{name: "RESPOND", input: "RESPOND", want: ActionRespond},
		{name: "unknown", input: "INVALID", wantErr: true},
		{name: "empty", input: "", wantErr: true},
		{name: "lowercase", input: "continue", wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ParseActionType(tt.input)
			if (err != nil) != tt.wantErr {
				t.Errorf("ParseActionType(%q) error = %v, wantErr %v", tt.input, err, tt.wantErr)
				return
			}
			if !tt.wantErr && got != tt.want {
				t.Errorf("ParseActionType(%q) = %v, want %v", tt.input, got, tt.want)
			}
		})
	}
}
