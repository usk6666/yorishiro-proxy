package http2

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"log/slog"
	gohttp "net/http"
	"strings"

	"github.com/usk6666/yorishiro-proxy/internal/plugin"
	"github.com/usk6666/yorishiro-proxy/internal/protocol/http2/hpack"
)

// dispatchOnReceiveFromClient dispatches the on_receive_from_client hook.
// It may return ActionDrop (return 502) or ActionRespond (send custom response).
// Returns the (possibly modified) request, body, and a boolean indicating the
// request was terminated (caller should return early).
// The txCtx is a mutable dict shared across all hooks within the same transaction.
// rawFrames contains the raw HTTP/2 frame bytes received from the client,
// which are injected into the hook data as an optional "raw_frames" field.
func (h *Handler) dispatchOnReceiveFromClient(ctx context.Context, w h2ResponseWriter, req *gohttp.Request, body []byte, connInfo *plugin.ConnInfo, txCtx map[string]any, rawFrames [][]byte, logger *slog.Logger) (*gohttp.Request, []byte, bool) {
	if h.pluginEngine == nil {
		return req, body, false
	}

	data := plugin.HTTPRequestToMap(req, body, connInfo, "h2")
	plugin.InjectRawFrames(data, rawFrames)
	plugin.InjectTxCtx(data, txCtx)

	result, err := h.pluginEngine.Dispatch(ctx, plugin.HookOnReceiveFromClient, data)
	if err != nil {
		logger.Warn("plugin on_receive_from_client error", "error", err)
		return req, body, false
	}
	plugin.ExtractTxCtx(result, txCtx)
	if result == nil {
		return req, body, false
	}

	switch result.Action {
	case plugin.ActionDrop:
		writeErrorResponse(w, gohttp.StatusBadGateway)
		logger.Info("plugin dropped request", "hook", "on_receive_from_client",
			"method", req.Method, "url", req.URL.String())
		return req, body, true

	case plugin.ActionRespond:
		writePluginRespondResponse(w, result.ResponseData, logger)
		logger.Info("plugin responded to request", "hook", "on_receive_from_client",
			"method", req.Method, "url", req.URL.String())
		return req, body, true

	case plugin.ActionContinue:
		if result.Data != nil {
			var applyErr error
			req, body, applyErr = plugin.ApplyHTTPRequestChanges(req, result.Data)
			if applyErr != nil {
				logger.Warn("plugin on_receive_from_client apply changes failed", "error", applyErr)
				return req, body, false
			}
			// Update request body if changed by plugin.
			if body != nil {
				req.Body = io.NopCloser(bytes.NewReader(body))
				req.ContentLength = int64(len(body))
			}
		}
	}

	return req, body, false
}

// dispatchOnBeforeSendToServer dispatches the on_before_send_to_server hook.
// Returns the (possibly modified) request and body.
// The txCtx is a mutable dict shared across all hooks within the same transaction.
// rawFrames contains the raw HTTP/2 frame bytes received from the client,
// which are injected into the hook data as an optional "raw_frames" field.
func (h *Handler) dispatchOnBeforeSendToServer(ctx context.Context, req *gohttp.Request, body []byte, connInfo *plugin.ConnInfo, txCtx map[string]any, rawFrames [][]byte, logger *slog.Logger) (*gohttp.Request, []byte) {
	if h.pluginEngine == nil {
		return req, body
	}

	data := plugin.HTTPRequestToMap(req, body, connInfo, "h2")
	plugin.InjectRawFrames(data, rawFrames)
	plugin.InjectTxCtx(data, txCtx)

	result, err := h.pluginEngine.Dispatch(ctx, plugin.HookOnBeforeSendToServer, data)
	if err != nil {
		logger.Warn("plugin on_before_send_to_server error", "error", err)
		return req, body
	}
	plugin.ExtractTxCtx(result, txCtx)
	if result == nil || result.Data == nil {
		return req, body
	}

	var applyErr error
	req, body, applyErr = plugin.ApplyHTTPRequestChanges(req, result.Data)
	if applyErr != nil {
		logger.Warn("plugin on_before_send_to_server apply changes failed", "error", applyErr)
		return req, body
	}
	if body != nil {
		req.Body = io.NopCloser(bytes.NewReader(body))
		req.ContentLength = int64(len(body))
	}

	return req, body
}

// dispatchOnReceiveFromServer dispatches the on_receive_from_server hook.
// Returns the (possibly modified) response and body.
// The txCtx is a mutable dict shared across all hooks within the same transaction.
// rawFrames contains the raw HTTP/2 frame bytes received from the upstream server,
// which are injected into the hook data as an optional "raw_frames" field.
func (h *Handler) dispatchOnReceiveFromServer(ctx context.Context, resp *gohttp.Response, body []byte, req *gohttp.Request, connInfo *plugin.ConnInfo, txCtx map[string]any, rawFrames [][]byte, logger *slog.Logger) (*gohttp.Response, []byte) {
	if h.pluginEngine == nil {
		return resp, body
	}

	data := plugin.HTTPResponseToMap(resp, body, req, connInfo, "h2")
	if rawFrames != nil {
		plugin.InjectRawFrames(data, rawFrames)
	}
	plugin.InjectTxCtx(data, txCtx)

	result, err := h.pluginEngine.Dispatch(ctx, plugin.HookOnReceiveFromServer, data)
	if err != nil {
		logger.Warn("plugin on_receive_from_server error", "error", err)
		return resp, body
	}
	plugin.ExtractTxCtx(result, txCtx)
	if result == nil || result.Data == nil {
		return resp, body
	}

	var applyErr error
	resp, body, applyErr = plugin.ApplyHTTPResponseChanges(resp, result.Data)
	if applyErr != nil {
		logger.Warn("plugin on_receive_from_server apply changes failed", "error", applyErr)
	}
	if body != nil {
		resp.ContentLength = int64(len(body))
	}

	return resp, body
}

// dispatchOnBeforeSendToClient dispatches the on_before_send_to_client hook.
// Returns the (possibly modified) response and body.
// The txCtx is a mutable dict shared across all hooks within the same transaction.
// rawFrames contains the raw HTTP/2 frame bytes received from the upstream server,
// which are injected into the hook data as an optional "raw_frames" field.
func (h *Handler) dispatchOnBeforeSendToClient(ctx context.Context, resp *gohttp.Response, body []byte, req *gohttp.Request, connInfo *plugin.ConnInfo, txCtx map[string]any, rawFrames [][]byte, logger *slog.Logger) (*gohttp.Response, []byte) {
	if h.pluginEngine == nil {
		return resp, body
	}

	data := plugin.HTTPResponseToMap(resp, body, req, connInfo, "h2")
	if rawFrames != nil {
		plugin.InjectRawFrames(data, rawFrames)
	}
	plugin.InjectTxCtx(data, txCtx)

	result, err := h.pluginEngine.Dispatch(ctx, plugin.HookOnBeforeSendToClient, data)
	if err != nil {
		logger.Warn("plugin on_before_send_to_client error", "error", err)
		return resp, body
	}
	plugin.ExtractTxCtx(result, txCtx)
	if result == nil || result.Data == nil {
		return resp, body
	}

	var applyErr error
	resp, body, applyErr = plugin.ApplyHTTPResponseChanges(resp, result.Data)
	if applyErr != nil {
		logger.Warn("plugin on_before_send_to_client apply changes failed", "error", applyErr)
	}
	if body != nil {
		resp.ContentLength = int64(len(body))
	}

	return resp, body
}

// writePluginRespondResponse writes a plugin ActionRespond response to the
// client. It filters hop-by-hop and duplicate content-length headers, then
// adds an authoritative content-length based on the actual body length.
func writePluginRespondResponse(w h2ResponseWriter, responseData map[string]any, logger *slog.Logger) {
	statusCode, pluginHeaders, respBody := plugin.BuildRespondResponse(responseData)
	var hpackHeaders []hpack.HeaderField
	for _, hdr := range pluginHeaders {
		// HTTP/2 requires lowercase header names (RFC 9113 §8.2).
		name := strings.ToLower(hdr.Name)
		// Filter pseudo-headers (WriteHeaders injects :status),
		// hop-by-hop headers (RFC 9113 §8.2.2), and plugin-provided
		// content-length (we add the authoritative value below).
		if strings.HasPrefix(name, ":") || isHopByHopHeader(name) || name == "content-length" {
			continue
		}
		hpackHeaders = append(hpackHeaders, hpack.HeaderField{Name: name, Value: hdr.Value})
	}
	// RFC 9110 §6.4.1: 1xx, 204, 205, and 304 must not include a body.
	noBody := isNoBodyStatus(statusCode)
	if noBody {
		respBody = nil
	} else {
		hpackHeaders = append(hpackHeaders, hpack.HeaderField{
			Name: "content-length", Value: fmt.Sprintf("%d", len(respBody)),
		})
	}
	if err := w.WriteHeaders(statusCode, hpackHeaders); err != nil {
		logger.Debug("failed to write plugin respond headers", "error", err)
		return
	}
	if len(respBody) > 0 {
		if err := w.WriteData(respBody); err != nil {
			logger.Debug("failed to write plugin respond body", "error", err)
		}
	}
}
