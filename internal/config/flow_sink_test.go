package config

import (
	"strings"
	"testing"
)

func TestFlowSinkConfig_Validate(t *testing.T) {
	cases := []struct {
		name    string
		json    string
		wantErr string // empty: valid
	}{
		{"absent", `{}`, ""},
		{"minimal", `{"flow_sink":{"dir":"/var/lib/yp/sink"}}`, ""},
		{"all fields", `{"flow_sink":{"dir":"sink","max_file_bytes":1048576,"max_files":10,"queue_max_events":100,"queue_max_bytes":1048576,"include_bodies":false,"wire_level":"all","fsync":true}}`, ""},
		{"wire_level semantic", `{"flow_sink":{"dir":"d","wire_level":"semantic"}}`, ""},
		{"wire_level overlay", `{"flow_sink":{"dir":"d","wire_level":"h2-frame"}}`, ""},
		{"empty dir", `{"flow_sink":{"dir":""}}`, "flow_sink.dir"},
		{"whitespace dir", `{"flow_sink":{"dir":"  "}}`, "flow_sink.dir"},
		{"missing dir", `{"flow_sink":{"max_files":1}}`, "flow_sink.dir"},
		{"negative max_file_bytes", `{"flow_sink":{"dir":"d","max_file_bytes":-1}}`, "flow_sink.max_file_bytes"},
		{"negative max_files", `{"flow_sink":{"dir":"d","max_files":-1}}`, "flow_sink.max_files"},
		{"negative queue_max_events", `{"flow_sink":{"dir":"d","queue_max_events":-1}}`, "flow_sink.queue_max_events"},
		{"negative queue_max_bytes", `{"flow_sink":{"dir":"d","queue_max_bytes":-1}}`, "flow_sink.queue_max_bytes"},
		{"unknown wire_level", `{"flow_sink":{"dir":"d","wire_level":"frames"}}`, "flow_sink.wire_level"},
		{"uppercase wire_level", `{"flow_sink":{"dir":"d","wire_level":"Semantic"}}`, "flow_sink.wire_level"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg, err := ParseFile("test.json", []byte(tc.json))
			if err != nil {
				t.Fatalf("ParseFile: %v", err)
			}
			err = cfg.Validate()
			if tc.wantErr == "" {
				if err != nil {
					t.Fatalf("Validate: %v, want nil", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("Validate = %v, want an error naming %q", err, tc.wantErr)
			}
		})
	}
}

func TestFlowSinkConfig_Resolved(t *testing.T) {
	no := false
	cases := []struct {
		name string
		cfg  FlowSinkConfig
		want ResolvedFlowSink
	}{
		{"defaults", FlowSinkConfig{Dir: "d"}, ResolvedFlowSink{
			Dir: "d", MaxFileBytes: 64 << 20, QueueMaxEvents: 4096, QueueMaxBytes: 256 << 20,
			IncludeBodies: true, WireLevel: "semantic",
		}},
		{"overrides", FlowSinkConfig{Dir: "d", MaxFileBytes: 10, MaxFiles: 3, QueueMaxEvents: 5, QueueMaxBytes: 7, IncludeBodies: &no, WireLevel: "all", Fsync: true}, ResolvedFlowSink{
			Dir: "d", MaxFileBytes: 10, MaxFiles: 3, QueueMaxEvents: 5, QueueMaxBytes: 7,
			IncludeBodies: false, WireLevel: "", Fsync: true,
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.cfg.Resolved(); got != tc.want {
				t.Errorf("Resolved() = %+v, want %+v", got, tc.want)
			}
		})
	}
}
