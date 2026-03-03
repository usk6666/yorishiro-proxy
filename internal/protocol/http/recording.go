package http

import (
	"context"
	"log/slog"
	gohttp "net/http"
	"net/url"
	"time"

	"github.com/usk6666/yorishiro-proxy/internal/config"
	"github.com/usk6666/yorishiro-proxy/internal/protocol/httputil"
	"github.com/usk6666/yorishiro-proxy/internal/session"
)

// sessionRecordParams holds all the parameters needed to record an HTTP/HTTPS
// session and its request/response messages to the session store.
type sessionRecordParams struct {
	// Session-level fields
	connID     string
	clientAddr string
	serverAddr string
	protocol   string
	start      time.Time
	duration   time.Duration
	tags       map[string]string
	connInfo   *session.ConnectionInfo

	// Request fields
	req          *gohttp.Request
	reqURL       *url.URL
	reqBody      []byte
	rawRequest   []byte
	reqTruncated bool

	// Response fields
	resp        *gohttp.Response
	rawResponse []byte
	respBody    []byte
}

// recordHTTPSession records a complete HTTP/HTTPS session (request + response)
// to the session store. It handles response body decompression for the stored
// copy while preserving raw bytes for wire-level analysis.
//
// This method is shared between handleRequest (HTTP) and handleHTTPSRequest
// (HTTPS MITM) to eliminate duplicate session recording code.
func (h *Handler) recordHTTPSession(ctx context.Context, p sessionRecordParams, logger *slog.Logger) {
	if h.Store == nil {
		return
	}

	reqURL := p.reqURL
	if reqURL == nil {
		reqURL = p.req.URL
	}

	if !h.shouldCapture(p.req.Method, reqURL) {
		return
	}

	// Decompress response body for recording. The raw (potentially compressed)
	// bytes are preserved in rawResponse for wire-level analysis.
	recordRespBody := p.respBody
	var respTruncated bool
	decompressed := false
	if p.resp != nil {
		if ce := p.resp.Header.Get("Content-Encoding"); ce != "" {
			decoded, err := httputil.DecompressBody(p.respBody, ce, config.MaxBodySize)
			if err != nil {
				logger.Debug("response body decompression failed, storing as-is", "encoding", ce, "error", err)
			} else {
				recordRespBody = decoded
				decompressed = true
			}
		}
	}
	if len(recordRespBody) > int(config.MaxBodySize) {
		recordRespBody = recordRespBody[:int(config.MaxBodySize)]
		respTruncated = true
	}

	sess := &session.Session{
		ConnID:      p.connID,
		Protocol:    p.protocol,
		SessionType: "unary",
		State:       "complete",
		Timestamp:   p.start,
		Duration:    p.duration,
		Tags:        p.tags,
		ConnInfo:    p.connInfo,
	}
	if err := h.Store.SaveSession(ctx, sess); err != nil {
		logger.Error("session save failed", "method", p.req.Method, "url", reqURL.String(), "error", err)
		return
	}

	sendMsg := &session.Message{
		SessionID:     sess.ID,
		Sequence:      0,
		Direction:     "send",
		Timestamp:     p.start,
		Method:        p.req.Method,
		URL:           reqURL,
		Headers:       p.req.Header,
		Body:          p.reqBody,
		RawBytes:      p.rawRequest,
		BodyTruncated: p.reqTruncated,
	}
	if err := h.Store.AppendMessage(ctx, sendMsg); err != nil {
		logger.Error("send message save failed", "error", err)
	}

	if p.resp != nil {
		recvMsg := &session.Message{
			SessionID:     sess.ID,
			Sequence:      1,
			Direction:     "receive",
			Timestamp:     p.start.Add(p.duration),
			StatusCode:    p.resp.StatusCode,
			Headers:       httputil.RecordingHeaders(p.resp.Header, decompressed, len(recordRespBody)),
			Body:          recordRespBody,
			RawBytes:      p.rawResponse,
			BodyTruncated: respTruncated,
		}
		if err := h.Store.AppendMessage(ctx, recvMsg); err != nil {
			logger.Error("receive message save failed", "error", err)
		}
	}
}
