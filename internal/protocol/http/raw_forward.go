package http

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"log/slog"
	"net"
	gohttp "net/http"
	"time"

	"github.com/usk6666/yorishiro-proxy/internal/protocol/httputil"
	"github.com/usk6666/yorishiro-proxy/internal/proxy/intercept"
)

// rawForwardResult holds the result of raw forwarding to the upstream server.
type rawForwardResult struct {
	// rawResponse is the complete raw response bytes from upstream.
	rawResponse []byte
	// resp is the parsed HTTP response (best-effort parse of the raw bytes).
	// May be nil if the raw response cannot be parsed as HTTP.
	resp *gohttp.Response
	// respBody is the response body extracted from the parsed response.
	// Empty if resp is nil.
	respBody []byte
	// serverAddr is the remote address of the upstream connection.
	serverAddr string
}

// forwardRawUpstream dials the upstream server, writes rawBytes directly to the
// connection, reads the raw response, and returns both the raw bytes and a
// best-effort parsed HTTP response.
//
// This bypasses net/http.Transport entirely, enabling HTTP Request Smuggling
// patterns (CL+TE conflicts, chunked encoding tricks, etc.) to be sent as-is.
func (h *Handler) forwardRawUpstream(ctx context.Context, req *gohttp.Request, rawBytes []byte, logger *slog.Logger) (*rawForwardResult, error) {
	// Determine the upstream address from the request URL.
	host := req.URL.Host
	if host == "" {
		host = req.Host
	}
	addr := host
	scheme := req.URL.Scheme
	if scheme == "" {
		scheme = "http"
	}

	// Add default port if not specified.
	if _, _, err := net.SplitHostPort(addr); err != nil {
		switch scheme {
		case "https":
			addr = addr + ":443"
		default:
			addr = addr + ":80"
		}
	}

	// Dial upstream using the handler's dial method (supports upstream proxy).
	upstream, err := h.dialRawUpstream(ctx, addr, scheme, host)
	if err != nil {
		return nil, fmt.Errorf("raw forward dial upstream %s: %w", addr, err)
	}
	defer upstream.Close()

	serverAddr := upstream.RemoteAddr().String()

	// Set a deadline for the entire raw forwarding operation.
	if deadline, ok := ctx.Deadline(); ok {
		upstream.SetDeadline(deadline)
	} else {
		upstream.SetDeadline(time.Now().Add(60 * time.Second))
	}

	// Write the raw bytes directly to the upstream connection.
	if _, err := upstream.Write(rawBytes); err != nil {
		return nil, fmt.Errorf("raw forward write: %w", err)
	}

	// Read the raw response from upstream.
	rawResponse, resp, respBody, err := readRawResponse(upstream)
	if err != nil {
		return nil, fmt.Errorf("raw forward read response: %w", err)
	}

	return &rawForwardResult{
		rawResponse: rawResponse,
		resp:        resp,
		respBody:    respBody,
		serverAddr:  serverAddr,
	}, nil
}

// dialRawUpstream establishes a TCP/TLS connection to the upstream server.
// For HTTPS targets, it performs a TLS handshake using the handler's TLS
// transport configuration.
func (h *Handler) dialRawUpstream(ctx context.Context, addr, scheme, host string) (net.Conn, error) {
	// Dial the TCP connection (supports upstream proxy).
	rawConn, err := h.dialUpstream(ctx, addr, 30*time.Second)
	if err != nil {
		return nil, err
	}

	// For HTTPS, wrap with TLS.
	if scheme == "https" {
		hostname, _, splitErr := net.SplitHostPort(addr)
		if splitErr != nil {
			hostname = addr
		}

		tlsTransport := h.effectiveTLSTransport()
		tlsConn, _, tlsErr := tlsTransport.TLSConnect(ctx, rawConn, hostname)
		if tlsErr != nil {
			rawConn.Close()
			return nil, fmt.Errorf("TLS connect: %w", tlsErr)
		}
		return tlsConn, nil
	}

	return rawConn, nil
}

// readRawResponse reads the complete response from the upstream connection.
// It captures the raw bytes while also attempting a best-effort HTTP parse
// so that the response can be recorded with structured L7 data.
func readRawResponse(conn net.Conn) (rawResponse []byte, resp *gohttp.Response, respBody []byte, err error) {
	// Use a captureReader to record all bytes from upstream.
	capture := &captureReader{r: conn}
	reader := bufio.NewReader(capture)

	// Attempt to parse as HTTP response.
	resp, parseErr := gohttp.ReadResponse(reader, nil)
	if parseErr != nil {
		// If parsing fails, read whatever is available as raw bytes.
		// This can happen with intentionally malformed responses.
		remaining, _ := io.ReadAll(io.LimitReader(reader, int64(intercept.MaxRawBytesSize)))
		rawResponse = capture.Bytes()
		if len(remaining) > 0 && len(rawResponse) == 0 {
			rawResponse = remaining
		}
		return rawResponse, nil, nil, nil
	}
	defer resp.Body.Close()

	// Read the response body.
	respBody, err = io.ReadAll(io.LimitReader(resp.Body, int64(maxRawCaptureSize)))
	if err != nil {
		// Partial read is acceptable for raw forwarding.
		rawResponse = capture.Bytes()
		return rawResponse, resp, respBody, nil
	}

	// The raw response includes everything captured.
	rawResponse = capture.Bytes()

	return rawResponse, resp, respBody, nil
}

// writeRawResponseToClient writes raw response bytes directly to the client
// connection, bypassing HTTP serialization.
func writeRawResponseToClient(conn net.Conn, rawResponse []byte) error {
	if _, err := conn.Write(rawResponse); err != nil {
		return fmt.Errorf("write raw response: %w", err)
	}
	return nil
}

// handleRawForward performs raw bytes forwarding for intercepted requests.
// It records the send phase (with variant if modified), forwards raw bytes
// directly to the upstream server, reads the raw response, writes it back
// to the client, and records the receive phase.
//
// This method is called when applyIntercept returns IsRaw=true, bypassing
// the normal net/http.Transport pipeline.
func (h *Handler) handleRawForward(ctx context.Context, conn net.Conn, req *gohttp.Request, iResult interceptResult, sp sendRecordParams, snap *requestSnapshot, start time.Time, logger *slog.Logger) error {
	// Record the send phase with variant support for raw forwarding.
	// When OriginalRawBytes is set (modify_and_forward+raw), record both
	// original and modified variants.
	sendResult := h.recordRawSend(ctx, sp, iResult, snap, logger)

	// Forward raw bytes to the upstream server.
	sendStart := time.Now()
	rawFwd, err := h.forwardRawUpstream(ctx, req, iResult.RawBytes, logger)
	if err != nil {
		logger.Error("raw forward upstream failed", "method", req.Method, "url", req.URL.String(), "error", err)
		httputil.WriteHTTPError(conn, gohttp.StatusBadGateway, logger)
		h.recordSendError(ctx, sendResult, start, err, logger)
		return nil
	}

	// Write raw response back to the client.
	if err := writeRawResponseToClient(conn, rawFwd.rawResponse); err != nil {
		return err
	}

	// Record the receive phase.
	duration := time.Since(start)
	sendMs := time.Since(sendStart).Milliseconds()
	h.recordRawReceive(ctx, sendResult, rawFwd, start, duration, sendMs, logger)

	statusCode := 0
	if rawFwd.resp != nil {
		statusCode = rawFwd.resp.StatusCode
	}
	logHTTPRequest(logger, req, statusCode, duration)

	return nil
}

// recordRawSend records the send phase for raw forwarding. When the intercept
// action is modify_and_forward (OriginalRawBytes != nil), it records both the
// original and modified raw bytes as variant messages.
func (h *Handler) recordRawSend(ctx context.Context, sp sendRecordParams, iResult interceptResult, snap *requestSnapshot, logger *slog.Logger) *sendRecordResult {
	if iResult.OriginalRawBytes != nil {
		// modify_and_forward+raw: force variant recording because the
		// modification happened at the raw bytes level, not the parsed
		// HTTP level. requestModified() compares parsed headers/body which
		// are unchanged, so we must signal the variant explicitly.
		sp.rawVariant = true
		sp.originalRawBytes = iResult.OriginalRawBytes
		sp.rawRequest = iResult.RawBytes
		return h.recordSendWithVariant(ctx, sp, snap, logger)
	}
	// release+raw: record the original raw bytes as-is (no variant needed).
	return h.recordSendWithVariant(ctx, sp, snap, logger)
}

// recordRawReceive records the receive phase for raw forwarding.
func (h *Handler) recordRawReceive(ctx context.Context, sendResult *sendRecordResult, rawFwd *rawForwardResult, start time.Time, duration time.Duration, sendMs int64, logger *slog.Logger) {
	if sendResult == nil || h.Store == nil {
		return
	}

	rp := receiveRecordParams{
		start:       start,
		duration:    duration,
		serverAddr:  rawFwd.serverAddr,
		resp:        rawFwd.resp,
		rawResponse: rawFwd.rawResponse,
		respBody:    rawFwd.respBody,
		sendMs:      &sendMs,
	}

	h.recordReceive(ctx, sendResult, rp, logger)
}
