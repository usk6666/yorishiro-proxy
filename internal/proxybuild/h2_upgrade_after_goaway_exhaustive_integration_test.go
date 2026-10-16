//go:build e2e && !e2e_smoke

// USK-1164 exhaustive-tier coverage. Reuses goAwayUpgradeOrigin and
// upgradeClient from h2_upgrade_after_goaway_integration_test.go.
package proxybuild_test

import (
	"bytes"
	"context"
	"strconv"
	"testing"
	"time"

	"golang.org/x/net/http2/hpack"

	"github.com/usk6666/yorishiro-proxy/internal/layer/ws"
)

// TestH2UpstreamGoAway_SSEUpgradeDoesNotHijackLiveFirstConnStream: conn #1
// keeps its stream 1 live (a long-poll that has sent only response
// HEADERS) across its GOAWAY. The SSE request then lands on the redialed
// conn #2, where it is ALSO upstream stream 1. Upgrading it must detach
// conn #2's stream: the long-poll body belongs to client stream 1 alone,
// and the SSE client must see only SSE bytes.
func TestH2UpstreamGoAway_SSEUpgradeDoesNotHijackLiveFirstConnStream(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	origin := startGoAwayUpgradeOrigin(t, upgradeModeLongPollSSE)
	store := &flowStoreForH2Pool{}
	proxyAddr := startProxyForRefusedTest(t, ctx, store)

	cli := newUpgradeClient(t, proxyAddr, origin.addr)
	cli.sendGET(t, 1, origin.addr, "/long-poll")
	waitGoAwaySent(t, origin)

	id := cli.openWithRefusedRetry(t, 3, func(id uint32) { cli.sendGET(t, id, origin.addr, sseEventsPath) })
	poll, sse := cli.result(1), cli.result(id)
	cli.readUntil(10*time.Second, func() bool { return poll.done() && sse.done() })
	assertRedialed(t, origin)

	if got := poll.body.String(); got != longPollBody || !poll.ended {
		t.Errorf("stream 1 (long-poll on conn #1): body=%q ended=%v rst=%v(%v); want %q + END_STREAM",
			got, poll.ended, poll.rst, poll.rstCode, longPollBody)
	}
	want := sseEvent1 + sseEvent2
	if got := sse.body.String(); got != want || !sse.ended {
		t.Errorf("stream %d (SSE on conn #2): body=%q ended=%v rst=%v(%v); want %q + END_STREAM",
			id, got, sse.ended, sse.rst, sse.rstCode, want)
	}
	if bytes.Contains(sse.body.Bytes(), []byte(longPollBody)) {
		t.Errorf("SSE client received the conn #1 long-poll body (cross-stream delivery)")
	}

	assertSSEEventsRecorded(t, store)
}

// TestH2UpstreamGoAway_WSOverH2OnRedialedConnectionEchoes: the extended
// CONNECT (RFC 8441) is opened on the redialed conn #2 after conn #1's
// GOAWAY. The WS frame must round-trip through conn #2's echo, and the
// session must be recorded as a Protocol=ws Stream whose frame flows carry
// wire raw bytes.
func TestH2UpstreamGoAway_WSOverH2OnRedialedConnectionEchoes(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	origin := startGoAwayUpgradeOrigin(t, upgradeModeWS)
	store := &flowStoreForH2Pool{}
	proxyAddr := startProxyForRefusedTest(t, ctx, store)

	cli := newUpgradeClient(t, proxyAddr, origin.addr)
	cli.sendGET(t, 1, origin.addr, "/plain")
	if !cli.readUntil(10*time.Second, cli.result(1).done) {
		t.Fatalf("stream 1 did not complete: %+v", cli.result(1))
	}
	waitGoAwaySent(t, origin)

	id := cli.openWithRefusedRetry(t, 3, func(id uint32) {
		cli.sendHeaders(t, id, false,
			hpack.HeaderField{Name: ":method", Value: "CONNECT"},
			hpack.HeaderField{Name: ":protocol", Value: "websocket"},
			hpack.HeaderField{Name: ":scheme", Value: "https"},
			hpack.HeaderField{Name: ":authority", Value: origin.addr},
			hpack.HeaderField{Name: ":path", Value: "/ws"},
			hpack.HeaderField{Name: "sec-websocket-version", Value: "13"},
		)
	})
	r := cli.result(id)
	if len(r.statuses) == 0 || r.statuses[0] != "200" {
		t.Fatalf("extended CONNECT on stream %d: statuses=%v rst=%v(%v) ended=%v; want 200", id, r.statuses, r.rst, r.rstCode, r.ended)
	}
	assertRedialed(t, origin)

	const payload = "hello-over-redialed-h2"
	var frame bytes.Buffer
	// RFC 8441 §5.3: no masking over h2.
	if err := ws.WriteFrame(&frame, &ws.Frame{Fin: true, Opcode: ws.OpcodeText, Payload: []byte(payload)}); err != nil {
		t.Fatalf("encode WS frame: %v", err)
	}
	if err := cli.fr.WriteData(id, false, frame.Bytes()); err != nil {
		t.Fatalf("write WS DATA: %v", err)
	}
	echoed := func() bool {
		if r.done() {
			return true
		}
		f, err := ws.ReadFrame(bytes.NewReader(r.body.Bytes()))
		return err == nil && string(f.Payload) == payload
	}
	cli.readUntil(10*time.Second, echoed)
	f, err := ws.ReadFrame(bytes.NewReader(r.body.Bytes()))
	if err != nil || string(f.Payload) != payload {
		t.Fatalf("WS echo on stream %d: body=%q rst=%v(%v) ended=%v decodeErr=%v; want echoed text frame %q",
			id, r.body.String(), r.rst, r.rstCode, r.ended, err, payload)
	}

	waitRecorded(t, 5*time.Second, "WS recording", func() (bool, string) {
		wsStreams := streamsWithProtocol(store, "ws")
		if len(wsStreams) != 1 {
			return false, "Protocol=ws streams = " + strconv.Itoa(len(wsStreams)) + ", want 1"
		}
		id := wsStreams[0].ID
		for _, dir := range []string{"send", "receive"} {
			found := false
			for _, fl := range semanticFlows(store, id, dir) {
				if string(fl.Body) == payload && len(fl.RawBytes) > 0 {
					found = true
				}
			}
			if !found {
				return false, "no " + dir + " WS frame flow with body " + strconv.Quote(payload) + " and non-empty RawBytes"
			}
		}
		return true, ""
	})
}
