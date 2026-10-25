package common

import (
	"context"
	"errors"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/usk6666/yorishiro-proxy/internal/envelope"
	"github.com/usk6666/yorishiro-proxy/internal/envelope/bodybuf"
)

// spillPrefix names the temp files created by newSpilledEnvelope so
// countQueueSpillFiles can find them.
const spillPrefix = "queue-spill"

// newSpilledEnvelope builds an HTTP envelope whose body and wire body both
// live in file-backed BodyBuffers, each at refCount=1 — the reference the
// producing Layer hands to the session. The test plays the session: once
// the hold is over it releases that single reference via ReleaseBuffers,
// after which no spill file may remain.
func newSpilledEnvelope(t *testing.T, dir string) *envelope.Envelope {
	t.Helper()
	newBuf := func(payload string) *bodybuf.BodyBuffer {
		buf, err := bodybuf.NewFile(dir, spillPrefix, 0)
		if err != nil {
			t.Fatalf("bodybuf.NewFile: %v", err)
		}
		if _, err := buf.Write([]byte(payload)); err != nil {
			t.Fatalf("bodybuf.Write: %v", err)
		}
		return buf
	}
	return &envelope.Envelope{
		StreamID:  "s1",
		FlowID:    "f1",
		Direction: envelope.Send,
		Protocol:  envelope.ProtocolHTTP,
		Raw:       []byte("POST /spill HTTP/1.1\r\nContent-Length: 13\r\n\r\n"),
		RawBuffer: newBuf(`{"spilled":1}`),
		Message: &envelope.HTTPMessage{
			Method:     "POST",
			Path:       "/spill",
			BodyBuffer: newBuf(`{"spilled":1}`),
		},
	}
}

func countQueueSpillFiles(t *testing.T, dir string) int {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("ReadDir: %v", err)
	}
	n := 0
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), spillPrefix) {
			n++
		}
	}
	return n
}

// waitHeld polls until the queue holds want entries.
func waitHeld(t *testing.T, q *HoldQueue, want int) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for q.Len() < want {
		if time.Now().After(deadline) {
			t.Fatalf("queue holds %d entries, want %d", q.Len(), want)
		}
		time.Sleep(time.Millisecond)
	}
}

// TestHoldQueue_SpilledBody_RefcountsBalanced holds an envelope carrying
// file-backed buffers, inspects it through Get and List the way the MCP
// control plane does (releasing each returned clone), resolves the hold
// through every exit path, and then releases the session's single
// reference. Every Retain the queue took must have been matched by a
// Release by then, so the spill files are gone.
func TestHoldQueue_SpilledBody_RefcountsBalanced(t *testing.T) {
	tests := []struct {
		name string
		// resolve ends the hold. It returns the action the test expects
		// Hold to return, or nil when Hold is expected to fail.
		setup   func(q *HoldQueue)
		resolve func(t *testing.T, q *HoldQueue, id string, cancel context.CancelFunc) *HoldAction
	}{
		{
			name: "release",
			resolve: func(t *testing.T, q *HoldQueue, id string, _ context.CancelFunc) *HoldAction {
				a := &HoldAction{Type: ActionRelease}
				if err := q.Release(id, a); err != nil {
					t.Fatalf("Release: %v", err)
				}
				return a
			},
		},
		{
			name: "drop",
			resolve: func(t *testing.T, q *HoldQueue, id string, _ context.CancelFunc) *HoldAction {
				a := &HoldAction{Type: ActionDrop}
				if err := q.Release(id, a); err != nil {
					t.Fatalf("Release: %v", err)
				}
				return a
			},
		},
		{
			name: "modify_and_forward",
			resolve: func(t *testing.T, q *HoldQueue, id string, _ context.CancelFunc) *HoldAction {
				entry, err := q.Get(id)
				if err != nil {
					t.Fatalf("Get: %v", err)
				}
				defer entry.Envelope.ReleaseBuffers()
				a := &HoldAction{Type: ActionModifyAndForward, Modified: entry.Envelope.Clone()}
				if err := q.Release(id, a); err != nil {
					t.Fatalf("Release: %v", err)
				}
				return a
			},
		},
		{
			name:  "timeout",
			setup: func(q *HoldQueue) { q.SetTimeout(50 * time.Millisecond) },
			resolve: func(_ *testing.T, _ *HoldQueue, _ string, _ context.CancelFunc) *HoldAction {
				return &HoldAction{Type: ActionRelease}
			},
		},
		{
			name: "ctx_cancel",
			resolve: func(_ *testing.T, _ *HoldQueue, _ string, cancel context.CancelFunc) *HoldAction {
				cancel()
				return nil
			},
		},
		{
			name: "clear",
			resolve: func(_ *testing.T, q *HoldQueue, _ string, _ context.CancelFunc) *HoldAction {
				q.Clear()
				return &HoldAction{Type: ActionRelease}
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			q := NewHoldQueue()
			if tc.setup != nil {
				tc.setup(q)
			}
			env := newSpilledEnvelope(t, dir)

			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			type result struct {
				action *HoldAction
				err    error
			}
			done := make(chan result, 1)
			go func() {
				a, err := q.Hold(ctx, env, []string{"r"})
				done <- result{a, err}
			}()
			waitHeld(t, q, 1)

			// Control-plane inspection: every clone handed out is released
			// by its caller.
			for _, e := range q.List() {
				e.Envelope.ReleaseBuffers()
			}
			entries := q.List()
			if len(entries) != 1 {
				// The timeout case may already have expired; that is fine.
				for _, e := range entries {
					e.Envelope.ReleaseBuffers()
				}
			}
			var id string
			if len(entries) == 1 {
				id = entries[0].ID
				entries[0].Envelope.ReleaseBuffers()
			}

			want := tc.resolve(t, q, id, cancel)
			var got result
			select {
			case got = <-done:
			case <-time.After(2 * time.Second):
				t.Fatal("Hold did not return")
			}
			if want == nil {
				if !errors.Is(got.err, context.Canceled) {
					t.Fatalf("Hold err = %v, want context.Canceled", got.err)
				}
			} else {
				if got.err != nil {
					t.Fatalf("Hold err = %v", got.err)
				}
				if got.action.Type != want.Type {
					t.Fatalf("Hold action = %v, want %v", got.action.Type, want.Type)
				}
			}
			// The Hold caller owns a returned Modified envelope.
			if got.action != nil && got.action.Modified != nil {
				got.action.Modified.ReleaseBuffers()
			}

			// The session releases its single reference.
			env.ReleaseBuffers()
			if n := countQueueSpillFiles(t, dir); n != 0 {
				t.Errorf("%d spill files remain after the hold ended and the session released its reference, want 0", n)
			}
		})
	}
}

// TestHoldQueue_SpilledBody_CapacityRejectReleasesClone covers the
// queue-full auto-release path: Hold returns without enqueuing, so it must
// not keep the references its clone took.
func TestHoldQueue_SpilledBody_CapacityRejectReleasesClone(t *testing.T) {
	dir := t.TempDir()
	q := NewHoldQueue()
	q.SetMaxItems(1)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	blocker := testEnvelope()
	blockerDone := make(chan struct{})
	go func() {
		defer close(blockerDone)
		_, _ = q.Hold(ctx, blocker, nil)
	}()
	waitHeld(t, q, 1)

	env := newSpilledEnvelope(t, dir)
	a, err := q.Hold(context.Background(), env, nil)
	if err != nil || a.Type != ActionRelease {
		t.Fatalf("Hold over capacity = (%v, %v), want (release, nil)", a, err)
	}
	cancel()
	<-blockerDone

	env.ReleaseBuffers()
	if n := countQueueSpillFiles(t, dir); n != 0 {
		t.Errorf("%d spill files remain after a capacity-rejected hold, want 0", n)
	}
}

// TestHoldQueue_SpilledBody_ModifyRacingCancel races a modify_and_forward
// Release against the hold's ctx cancellation. Whichever side wins, the
// Modified envelope must be released exactly once: by the Hold caller when
// Hold returns it, by the queue when Hold returns the ctx error instead, or
// by the releaser when Release reports the entry gone. A double release
// panics; a missed one leaves a spill file.
func TestHoldQueue_SpilledBody_ModifyRacingCancel(t *testing.T) {
	dir := t.TempDir()
	for i := 0; i < 50; i++ {
		q := NewHoldQueue()
		env := newSpilledEnvelope(t, dir)
		ctx, cancel := context.WithCancel(context.Background())

		var holdAction *HoldAction
		var wg sync.WaitGroup
		wg.Add(1)
		go func() {
			defer wg.Done()
			holdAction, _ = q.Hold(ctx, env, nil)
		}()
		waitHeld(t, q, 1)
		entries := q.List()
		id := entries[0].ID
		modified := entries[0].Envelope // the List clone becomes the Modified envelope

		go cancel()
		if err := q.Release(id, &HoldAction{Type: ActionModifyAndForward, Modified: modified}); err != nil {
			// Lost the race: the entry is gone and the releaser still
			// owns its envelope.
			modified.ReleaseBuffers()
		}
		wg.Wait()
		if holdAction != nil && holdAction.Modified != nil {
			holdAction.Modified.ReleaseBuffers()
		}
		cancel()
		env.ReleaseBuffers()
	}
	if n := countQueueSpillFiles(t, dir); n != 0 {
		t.Errorf("%d spill files remain after 50 modify/cancel races, want 0", n)
	}
}
