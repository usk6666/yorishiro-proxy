package tcp

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/usk6666/yorishiro-proxy/internal/config"
	"github.com/usk6666/yorishiro-proxy/internal/flow"
	"github.com/usk6666/yorishiro-proxy/internal/plugin"
)

// relayBufSize is the buffer size for bidirectional data relay.
// 32 KB balances memory usage and throughput for typical TCP traffic.
const relayBufSize = 32 * 1024

// relay copies data bidirectionally between a client and an upstream
// connection, recording each chunk as a message in the flow store.
type relay struct {
	store        flow.FlowWriter
	flowID       string
	logger       *slog.Logger
	pluginEngine *plugin.Engine
	connInfo     *plugin.ConnInfo
	target       string       // forward target address
	seq          atomic.Int64 // next message sequence number
}

// run performs the bidirectional relay until one side closes, an error occurs,
// or the context is cancelled.
func (r *relay) run(ctx context.Context, client, upstream net.Conn) error {
	// Wrap ctx in a relay-scoped cancel context so the watcher goroutine
	// exits when the relay terminates normally (e.g., peer EOF), not only
	// when the parent context is cancelled.
	relayCtx, relayCancel := context.WithCancel(ctx)
	defer relayCancel()

	// Watch for context cancellation and interrupt blocking reads.
	go func() {
		<-relayCtx.Done()
		client.SetReadDeadline(time.Now())
		upstream.SetReadDeadline(time.Now())
	}()

	var (
		once     sync.Once
		firstErr error
	)

	errCh := make(chan error, 2)

	// client -> upstream (send direction)
	go func() {
		err := r.copyAndRecord(ctx, upstream, client, "send")
		once.Do(func() { firstErr = err })
		errCh <- err
		// Signal the other goroutine by unblocking its read.
		upstream.SetReadDeadline(time.Now())
	}()

	// upstream -> client (receive direction)
	go func() {
		err := r.copyAndRecord(ctx, client, upstream, "receive")
		once.Do(func() { firstErr = err })
		errCh <- err
		// Signal the other goroutine by unblocking its read.
		client.SetReadDeadline(time.Now())
	}()

	// Wait for both goroutines.
	<-errCh
	<-errCh

	// Context cancellation is normal during shutdown.
	if ctx.Err() != nil {
		return ctx.Err()
	}

	return firstErr
}

// copyAndRecord reads from src and writes to dst, recording each chunk as a
// message in the flow store. The direction is "send" (client -> upstream)
// or "receive" (upstream -> client).
//
// Plugin hooks are dispatched per-chunk (bidirectional):
//   - "send" direction: on_receive_from_client -> on_before_send_to_server
//   - "receive" direction: on_receive_from_server -> on_before_send_to_client
//
// If a plugin returns ActionDrop, the chunk is silently skipped.
// If a plugin modifies the data, the modified data is forwarded.
// Plugin errors are logged but do not interrupt relay (fail-open).
func (r *relay) copyAndRecord(ctx context.Context, dst, src net.Conn, direction string) error {
	buf := make([]byte, relayBufSize)

	// Determine hook pair based on direction.
	var receiveHook, sendHook plugin.Hook
	var pluginDirection string
	if direction == "send" {
		receiveHook = plugin.HookOnReceiveFromClient
		sendHook = plugin.HookOnBeforeSendToServer
		pluginDirection = "client_to_server"
	} else {
		receiveHook = plugin.HookOnReceiveFromServer
		sendHook = plugin.HookOnBeforeSendToClient
		pluginDirection = "server_to_client"
	}

	for {
		n, readErr := src.Read(buf)
		if n > 0 {
			chunk := buf[:n]

			// Dispatch plugin hooks if engine is available.
			chunk, dropped := r.dispatchChunkHooks(ctx, chunk, receiveHook, sendHook, pluginDirection)
			if !dropped {
				// Write to destination first (low latency is more important than recording).
				if _, writeErr := dst.Write(chunk); writeErr != nil {
					return fmt.Errorf("write %s: %w", direction, writeErr)
				}

				// Record the chunk.
				r.record(ctx, direction, chunk)
			}
		}

		if readErr != nil {
			// Check context before returning the read error.
			if ctx.Err() != nil {
				return ctx.Err()
			}
			// EOF and other network close errors are normal termination.
			return nil
		}
	}
}

// dispatchChunkHooks dispatches the receive and send plugin hooks for a TCP chunk.
// It returns the (potentially modified) chunk data and whether the chunk should be dropped.
// Plugin errors are logged but do not interrupt relay (fail-open).
//
// A per-chunk transaction context is created so that plugins can pass data
// between the receive and send hooks for the same chunk.
func (r *relay) dispatchChunkHooks(ctx context.Context, chunk []byte, receiveHook, sendHook plugin.Hook, pluginDirection string) ([]byte, bool) {
	if r.pluginEngine == nil {
		return chunk, false
	}

	// Create a transaction context scoped to this chunk's hook pair.
	txCtx := plugin.NewTxCtx()

	// Dispatch receive hook.
	chunk, dropped := r.dispatchSingleHook(ctx, receiveHook, chunk, pluginDirection, txCtx)
	if dropped {
		return nil, true
	}

	// Dispatch send hook.
	chunk, dropped = r.dispatchSingleHook(ctx, sendHook, chunk, pluginDirection, txCtx)
	if dropped {
		return nil, true
	}

	return chunk, false
}

// dispatchSingleHook dispatches one plugin hook for a TCP chunk.
// It returns the (potentially modified) data and whether the chunk should be dropped.
// The txCtx is a mutable dict shared across the receive and send hooks for the same chunk.
func (r *relay) dispatchSingleHook(ctx context.Context, hook plugin.Hook, data []byte, pluginDirection string, txCtx map[string]any) ([]byte, bool) {
	hookData := r.buildChunkData(data, pluginDirection)
	plugin.InjectTxCtx(hookData, txCtx)

	result, err := r.pluginEngine.Dispatch(ctx, hook, hookData)
	if err != nil {
		r.logger.Warn("tcp plugin hook error",
			"flow_id", r.flowID,
			"hook", string(hook),
			"error", err,
		)
		return data, false // fail-open
	}

	if result == nil {
		return data, false
	}

	if result.Action == plugin.ActionDrop {
		r.logger.Debug("tcp chunk dropped by plugin",
			"flow_id", r.flowID,
			"hook", string(hook),
			"direction", pluginDirection,
		)
		return nil, true
	}

	// Apply data modifications from plugin result.
	if result.Data != nil {
		if newData, ok := result.Data["data"]; ok {
			var modified []byte
			switch p := newData.(type) {
			case []byte:
				modified = p
			case string:
				modified = []byte(p)
			}
			if modified != nil {
				if int64(len(modified)) > config.MaxTCPPluginChunkSize {
					r.logger.Warn("plugin modified chunk exceeds size limit, keeping original",
						"flow_id", r.flowID,
						"hook", string(hook),
						"modified_size", len(modified),
						"limit", config.MaxTCPPluginChunkSize,
					)
				} else {
					data = modified
				}
			}
		}
	}

	return data, false
}

// buildChunkData constructs the plugin hook data map for a TCP chunk.
func (r *relay) buildChunkData(data []byte, direction string) map[string]any {
	m := map[string]any{
		"protocol":       "tcp",
		"data":           data,
		"direction":      direction,
		"forward_target": r.target,
	}

	if r.connInfo != nil {
		m["conn_info"] = r.connInfo.ToMap()
	} else {
		m["conn_info"] = map[string]any{}
	}

	return m
}

// record appends a message to the flow store for one data chunk.
// Recording errors are logged but do not interrupt the relay.
func (r *relay) record(ctx context.Context, direction string, data []byte) {
	if r.store == nil {
		return
	}

	seq := int(r.seq.Add(1) - 1)

	// Copy the data to avoid aliasing the read buffer.
	raw := make([]byte, len(data))
	copy(raw, data)

	msg := &flow.Message{
		FlowID:    r.flowID,
		Sequence:  seq,
		Direction: direction,
		Timestamp: time.Now(),
		RawBytes:  raw,
		Metadata: map[string]string{
			"chunk_size": fmt.Sprintf("%d", len(data)),
		},
	}

	if err := r.store.AppendMessage(ctx, msg); err != nil {
		r.logger.Error("TCP message record failed",
			"flow_id", r.flowID,
			"seq", seq,
			"direction", direction,
			"error", err)
	}
}
