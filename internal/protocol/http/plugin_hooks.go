package http

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"log/slog"
	"net"
	gohttp "net/http"

	"github.com/usk6666/yorishiro-proxy/internal/plugin"
	"github.com/usk6666/yorishiro-proxy/internal/protocol/httputil"
)

// dispatchOnReceiveFromClient dispatches the on_receive_from_client hook.
// It may return ActionDrop (close connection) or ActionRespond (send custom response).
// Returns the (possibly modified) request, body, and a boolean indicating the
// request was terminated (caller should return early).
func (h *Handler) dispatchOnReceiveFromClient(ctx context.Context, conn net.Conn, req *gohttp.Request, body []byte, connInfo *plugin.ConnInfo, logger *slog.Logger) (*gohttp.Request, []byte, bool) {
	if h.pluginEngine == nil {
		return req, body, false
	}

	data := plugin.HTTPRequestToMap(req, body, connInfo, "HTTP/1.x")

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
		httputil.WriteHTTPError(conn, gohttp.StatusBadGateway, logger)
		logger.Info("plugin dropped request", "hook", "on_receive_from_client",
			"method", req.Method, "url", req.URL.String())
		return req, body, true

	case plugin.ActionRespond:
		statusCode, headers, respBody := plugin.BuildRespondResponse(result.ResponseData)
		if err := writePluginResponse(conn, statusCode, headers, respBody); err != nil {
			logger.Warn("plugin respond write failed", "error", err)
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

	data := plugin.HTTPRequestToMap(req, body, connInfo, "HTTP/1.x")

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

	data := plugin.HTTPResponseToMap(resp, body, req, connInfo, "HTTP/1.x")

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

	return resp, body
}

// dispatchOnBeforeSendToClient dispatches the on_before_send_to_client hook.
// Returns the (possibly modified) response and body.
func (h *Handler) dispatchOnBeforeSendToClient(ctx context.Context, resp *gohttp.Response, body []byte, req *gohttp.Request, connInfo *plugin.ConnInfo, logger *slog.Logger) (*gohttp.Response, []byte) {
	if h.pluginEngine == nil {
		return resp, body
	}

	data := plugin.HTTPResponseToMap(resp, body, req, connInfo, "HTTP/1.x")

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

	return resp, body
}

// writePluginResponse writes a custom HTTP response generated by a plugin's
// RESPOND action to the client connection.
func writePluginResponse(conn net.Conn, statusCode int, headers gohttp.Header, body []byte) error {
	resp := &gohttp.Response{
		StatusCode: statusCode,
		ProtoMajor: 1,
		ProtoMinor: 1,
		Header:     headers,
	}
	if resp.Header == nil {
		resp.Header = make(gohttp.Header)
	}
	resp.Header.Set("Content-Length", fmt.Sprintf("%d", len(body)))
	resp.Header.Set("Connection", "close")

	return writeResponse(conn, resp, body)
}
