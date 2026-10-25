package session

import (
	"context"
	"regexp"
	"testing"
	"time"

	"github.com/usk6666/yorishiro-proxy/internal/envelope"
	"github.com/usk6666/yorishiro-proxy/internal/envelope/bodybuf"
	"github.com/usk6666/yorishiro-proxy/internal/layer"
	"github.com/usk6666/yorishiro-proxy/internal/pipeline"
	"github.com/usk6666/yorishiro-proxy/internal/rules/common"
	httprules "github.com/usk6666/yorishiro-proxy/internal/rules/http"
	"github.com/usk6666/yorishiro-proxy/internal/testutil"
)

// These tests drive a held, disk-spilled request through the real
// InterceptStep + HoldQueue inside RunSession, resolving the hold the way
// the MCP intercept tool does: inspect via List/Get (releasing each clone),
// and for modify_and_forward hand back a Clone of the held envelope that
// owns its own buffer references. However the hold ends — and whatever the
// Steps after it do to the forwarded envelope — every reference must be
// released by the time RunSession returns, leaving no spill file.

// makeSpilledRequest builds a request envelope whose body (HTTPMessage
// .BodyBuffer) and wire body (Envelope.RawBuffer) are both file-backed at
// refCount=1, the references the HTTP/1.x Layer hands to the session.
func makeSpilledRequest(t *testing.T, dir string, body string) *envelope.Envelope {
	t.Helper()
	newBuf := func() *bodybuf.BodyBuffer {
		buf, err := bodybuf.NewFile(dir, bodyBufSpillPrefix, 1<<20)
		if err != nil {
			t.Fatalf("bodybuf.NewFile: %v", err)
		}
		if _, err := buf.Write([]byte(body)); err != nil {
			t.Fatalf("bodybuf.Write: %v", err)
		}
		return buf
	}
	return &envelope.Envelope{
		StreamID:  "s",
		FlowID:    "f",
		Direction: envelope.Send,
		Protocol:  envelope.ProtocolHTTP,
		Raw:       []byte("POST /spill HTTP/1.1\r\nHost: example.com\r\n\r\n"),
		RawBuffer: newBuf(),
		Message: &envelope.HTTPMessage{
			Method:     "POST",
			Path:       "/spill",
			Headers:    []envelope.KeyValue{{Name: "Host", Value: "example.com"}},
			BodyBuffer: newBuf(),
		},
	}
}

// dropRefsFromClone models the MCP body-replacement arm on an intercept
// modify clone: the clone's own BodyBuffer and RawBuffer references are
// released and the body moves to HTTPMessage.Body.
func dropRefsFromClone(mod *envelope.Envelope, body string) {
	hm := mod.Message.(*envelope.HTTPMessage)
	if hm.BodyBuffer != nil {
		_ = hm.BodyBuffer.Release()
		hm.BodyBuffer = nil
	}
	if mod.RawBuffer != nil {
		_ = mod.RawBuffer.Release()
		mod.RawBuffer = nil
	}
	hm.Body = []byte(body)
	mod.Raw = nil
}

// resolveFirstHold waits for the first held entry and resolves it with the
// action build returns. build receives a Get clone it may Clone from; the
// Get clone itself is released here.
func resolveFirstHold(t *testing.T, q *common.HoldQueue, build func(held *envelope.Envelope) *common.HoldAction) <-chan struct{} {
	t.Helper()
	done := make(chan struct{})
	go func() {
		defer close(done)
		deadline := time.Now().Add(5 * time.Second)
		var id string
		for id == "" {
			if time.Now().After(deadline) {
				t.Error("no entry appeared in the hold queue")
				return
			}
			for _, e := range q.List() {
				id = e.ID
				e.Envelope.ReleaseBuffers()
			}
			time.Sleep(time.Millisecond)
		}
		entry, err := q.Get(id)
		if err != nil {
			t.Errorf("Get: %v", err)
			return
		}
		defer entry.Envelope.ReleaseBuffers()
		action := build(entry.Envelope)
		if err := q.Release(id, action); err != nil {
			t.Errorf("Release: %v", err)
			if action.Modified != nil {
				action.Modified.ReleaseBuffers()
			}
		}
	}()
	return done
}

func TestRunSession_InterceptHold_SpilledBodyReleased(t *testing.T) {
	type tc struct {
		name string
		body string
		// safety enables the modify_and_forward safety re-check.
		safety bool
		// after are Steps appended after the InterceptStep.
		after []pipeline.Step
		build func(held *envelope.Envelope) *common.HoldAction
		// wantUpstream reports whether the request reaches the upstream.
		wantUpstream bool
	}
	keepBody := func(held *envelope.Envelope) *common.HoldAction {
		mod := held.Clone()
		mod.Raw = nil
		hm := mod.Message.(*envelope.HTTPMessage)
		hm.Headers = append(hm.Headers, envelope.KeyValue{Name: "X-Modified", Value: "1"})
		return &common.HoldAction{Type: common.ActionModifyAndForward, Modified: mod}
	}
	cases := []tc{
		{
			name:         "release",
			body:         `{"a":1}`,
			build:        func(*envelope.Envelope) *common.HoldAction { return &common.HoldAction{Type: common.ActionRelease} },
			wantUpstream: true,
		},
		{
			name:  "drop",
			body:  `{"a":1}`,
			build: func(*envelope.Envelope) *common.HoldAction { return &common.HoldAction{Type: common.ActionDrop} },
		},
		{
			name:         "modify_keeps_spilled_body",
			body:         `{"a":1}`,
			build:        keepBody,
			wantUpstream: true,
		},
		{
			name: "modify_replaces_spilled_body",
			body: `{"a":1}`,
			build: func(held *envelope.Envelope) *common.HoldAction {
				mod := held.Clone()
				dropRefsFromClone(mod, `{"a":2}`)
				return &common.HoldAction{Type: common.ActionModifyAndForward, Modified: mod}
			},
			wantUpstream: true,
		},
		{
			name:         "modify_then_transform_commit",
			body:         `{"a":1}`,
			after:        []pipeline.Step{transformReleaseStep{}},
			build:        keepBody,
			wantUpstream: true,
		},
		{
			name:   "modify_blocked_by_safety_recheck",
			body:   `DROP TABLE users;`,
			safety: true,
			build:  keepBody,
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			dir := t.TempDir()
			req := makeSpilledRequest(t, dir, c.body)
			if got := countSpillFiles(t, dir); got != 2 {
				t.Fatalf("setup: spill files = %d, want 2", got)
			}

			engine := httprules.NewInterceptEngine()
			engine.AddRule(httprules.InterceptRule{
				ID:          "hold-spill",
				Enabled:     true,
				Direction:   httprules.DirectionRequest,
				PathPattern: regexp.MustCompile(`^/spill$`),
			})
			q := common.NewHoldQueue()
			var safety *pipeline.SafetyStep
			if c.safety {
				se := httprules.NewSafetyEngine()
				if err := se.LoadPreset(common.PresetDestructiveSQL); err != nil {
					t.Fatalf("LoadPreset: %v", err)
				}
				safety = pipeline.NewSafetyStep(se, nil, nil, testutil.DiscardLogger())
			}
			steps := []pipeline.Step{pipeline.NewInterceptStep(engine, nil, nil, nil, q, safety, testutil.DiscardLogger())}
			steps = append(steps, c.after...)

			resolved := resolveFirstHold(t, q, c.build)

			resp := &envelope.Envelope{
				Direction: envelope.Receive,
				Protocol:  envelope.ProtocolHTTP,
				Message:   &envelope.HTTPMessage{Status: 200, Body: []byte("ok")},
			}
			clientCh := &mockChannel{streamID: "s", nextEnvelopes: []*envelope.Envelope{req}}
			upstreamCh := &mockChannel{streamID: "u", nextEnvelopes: []*envelope.Envelope{resp}}
			dialed := false
			dial := func(_ context.Context, _ *envelope.Envelope) (layer.Channel, error) {
				dialed = true
				return upstreamCh, nil
			}

			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			if err := RunSession(ctx, clientCh, dial, pipeline.New(steps...)); err != nil {
				t.Fatalf("RunSession: %v", err)
			}
			<-resolved

			if dialed != c.wantUpstream {
				t.Errorf("upstream dialed = %v, want %v", dialed, c.wantUpstream)
			}
			if got := countSpillFiles(t, dir); got != 0 {
				t.Errorf("after session: spill files = %d, want 0 (an intercept hold leaked a buffer reference)", got)
			}
		})
	}
}
