package http2

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"log/slog"
	gohttp "net/http"

	"github.com/usk6666/yorishiro-proxy/internal/plugin"
)

// dispatchOnReceiveFromClient dispatches the on_receive_from_client hook.
// It may return ActionDrop (return 502) or ActionRespond (send custom response).
// Returns the (possibly modified) request, body, and a boolean indicating the
// request was terminated (caller should return early).
func (h *Handler) dispatchOnReceiveFromClient(ctx context.Context, w gohttp.ResponseWriter, req *gohttp.Request, body []byte, connInfo *plugin.ConnInfo, logger *slog.Logger) (*gohttp.Request, []byte, bool) {
	if h.pluginEngine == nil {
		return req, body, false
	}

	data := plugin.HTTPRequestToMap(req, body, connInfo, "h2")

	result, err := h.pluginEngine.Dispatch(ctx, plugin.HookOnReceiveFromClient, data)
	if err != nil {
		logger.Warn("plugin on_receive_from_client error", "error", err)
		return req, body, false
	}
	if result == nil {
		return req, body, false
	}

	switch result.Action {
	case plugin.ActionDrop:
		w.WriteHeader(gohttp.StatusBadGateway)
		logger.Info("plugin dropped request", "hook", "on_receive_from_client",
			"method", req.Method, "url", req.URL.String())
		return req, body, true

	case plugin.ActionRespond:
		statusCode, headers, respBody := plugin.BuildRespondResponse(result.ResponseData)
		for key, vals := range headers {
			for _, val := range vals {
				w.Header().Add(key, val)
			}
		}
		w.Header().Set("Content-Length", fmt.Sprintf("%d", len(respBody)))
		w.WriteHeader(statusCode)
		if len(respBody) > 0 {
			w.Write(respBody)
		}
		logger.Info("plugin responded to request", "hook", "on_receive_from_client",
			"method", req.Method, "url", req.URL.String(), "status", statusCode)
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
func (h *Handler) dispatchOnBeforeSendToServer(ctx context.Context, req *gohttp.Request, body []byte, connInfo *plugin.ConnInfo, logger *slog.Logger) (*gohttp.Request, []byte) {
	if h.pluginEngine == nil {
		return req, body
	}

	data := plugin.HTTPRequestToMap(req, body, connInfo, "h2")

	result, err := h.pluginEngine.Dispatch(ctx, plugin.HookOnBeforeSendToServer, data)
	if err != nil {
		logger.Warn("plugin on_before_send_to_server error", "error", err)
		return req, body
	}
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
func (h *Handler) dispatchOnReceiveFromServer(ctx context.Context, resp *gohttp.Response, body []byte, req *gohttp.Request, connInfo *plugin.ConnInfo, logger *slog.Logger) (*gohttp.Response, []byte) {
	if h.pluginEngine == nil {
		return resp, body
	}

	data := plugin.HTTPResponseToMap(resp, body, req, connInfo, "h2")

	result, err := h.pluginEngine.Dispatch(ctx, plugin.HookOnReceiveFromServer, data)
	if err != nil {
		logger.Warn("plugin on_receive_from_server error", "error", err)
		return resp, body
	}
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
func (h *Handler) dispatchOnBeforeSendToClient(ctx context.Context, resp *gohttp.Response, body []byte, req *gohttp.Request, connInfo *plugin.ConnInfo, logger *slog.Logger) (*gohttp.Response, []byte) {
	if h.pluginEngine == nil {
		return resp, body
	}

	data := plugin.HTTPResponseToMap(resp, body, req, connInfo, "h2")

	result, err := h.pluginEngine.Dispatch(ctx, plugin.HookOnBeforeSendToClient, data)
	if err != nil {
		logger.Warn("plugin on_before_send_to_client error", "error", err)
		return resp, body
	}
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
