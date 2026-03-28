package http

import (
	"bytes"
	"context"
	"fmt"
	"log/slog"
	"net"

	"github.com/usk6666/yorishiro-proxy/internal/plugin"
	"github.com/usk6666/yorishiro-proxy/internal/protocol/http/parser"
	"github.com/usk6666/yorishiro-proxy/internal/protocol/httputil"
)

// dispatchOnReceiveFromClient dispatches the on_receive_from_client hook.
func (h *Handler) dispatchOnReceiveFromClient(ctx context.Context, conn net.Conn, req *parser.RawRequest, body []byte, connInfo *plugin.ConnInfo, txCtx map[string]any, logger *slog.Logger) (*parser.RawRequest, []byte, bool) {
	if h.pluginEngine == nil {
		return req, body, false
	}

	goReq := httputil.RawRequestToHTTP(req, body)
	data := plugin.HTTPRequestToMap(goReq, body, connInfo, "HTTP/1.x")
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
		writeHTTPError(conn, statusBadGateway, logger)
		logger.Info("plugin dropped request", "hook", "on_receive_from_client",
			"method", req.Method, "url", req.RequestURI)
		return req, body, true

	case plugin.ActionRespond:
		statusCode, headers, respBody := plugin.BuildRespondResponse(result.ResponseData)
		if err := writePluginResponseRaw(conn, statusCode, headers, respBody); err != nil {
			logger.Warn("plugin respond write failed", "error", err)
		}
		logger.Info("plugin responded to request", "hook", "on_receive_from_client",
			"method", req.Method, "url", req.RequestURI, "status", statusCode)
		return req, body, true

	case plugin.ActionContinue:
		if result.Data != nil {
			goReq, body, applyErr := plugin.ApplyHTTPRequestChanges(goReq, result.Data)
			if applyErr != nil {
				logger.Warn("plugin on_receive_from_client apply changes failed", "error", applyErr)
				return req, body, false
			}
			// Convert back to RawRequest.
			req = httputil.HTTPRequestToRaw(goReq, body)
		}
	}

	return req, body, false
}

// dispatchOnBeforeSendToServer dispatches the on_before_send_to_server hook.
func (h *Handler) dispatchOnBeforeSendToServer(ctx context.Context, req *parser.RawRequest, body []byte, connInfo *plugin.ConnInfo, txCtx map[string]any, logger *slog.Logger) (*parser.RawRequest, []byte) {
	if h.pluginEngine == nil {
		return req, body
	}

	goReq := httputil.RawRequestToHTTP(req, body)
	data := plugin.HTTPRequestToMap(goReq, body, connInfo, "HTTP/1.x")
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

	goReq, body, applyErr := plugin.ApplyHTTPRequestChanges(goReq, result.Data)
	if applyErr != nil {
		logger.Warn("plugin on_before_send_to_server apply changes failed", "error", applyErr)
		return req, body
	}
	req = httputil.HTTPRequestToRaw(goReq, body)

	return req, body
}

// dispatchOnReceiveFromServer dispatches the on_receive_from_server hook.
func (h *Handler) dispatchOnReceiveFromServer(ctx context.Context, resp *parser.RawResponse, body []byte, req *parser.RawRequest, connInfo *plugin.ConnInfo, txCtx map[string]any, logger *slog.Logger) (*parser.RawResponse, []byte) {
	if h.pluginEngine == nil {
		return resp, body
	}

	goReq := httputil.RawRequestToHTTP(req, nil)
	goResp := httputil.RawResponseToHTTP(resp, body)
	data := plugin.HTTPResponseToMap(goResp, body, goReq, connInfo, "HTTP/1.x")
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

	goResp, body, applyErr := plugin.ApplyHTTPResponseChanges(goResp, result.Data)
	if applyErr != nil {
		logger.Warn("plugin on_receive_from_server apply changes failed", "error", applyErr)
	}
	resp = httputil.HTTPResponseToRaw(goResp, body)

	return resp, body
}

// dispatchOnBeforeSendToClient dispatches the on_before_send_to_client hook.
func (h *Handler) dispatchOnBeforeSendToClient(ctx context.Context, resp *parser.RawResponse, body []byte, req *parser.RawRequest, connInfo *plugin.ConnInfo, txCtx map[string]any, logger *slog.Logger) (*parser.RawResponse, []byte) {
	if h.pluginEngine == nil {
		return resp, body
	}

	goReq := httputil.RawRequestToHTTP(req, nil)
	goResp := httputil.RawResponseToHTTP(resp, body)
	data := plugin.HTTPResponseToMap(goResp, body, goReq, connInfo, "HTTP/1.x")
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

	goResp, body, applyErr := plugin.ApplyHTTPResponseChanges(goResp, result.Data)
	if applyErr != nil {
		logger.Warn("plugin on_before_send_to_client apply changes failed", "error", applyErr)
	}
	resp = httputil.HTTPResponseToRaw(goResp, body)

	return resp, body
}

// writePluginResponseRaw writes a custom HTTP response generated by a plugin's
// RESPOND action using RawHeaders (without importing net/http).
func writePluginResponseRaw(conn net.Conn, statusCode int, headers parser.RawHeaders, body []byte) error {
	resp := &parser.RawResponse{
		Proto:      "HTTP/1.1",
		StatusCode: statusCode,
		Status:     formatStatus(statusCode),
		Headers:    headers,
		Body:       bytes.NewReader(body),
	}
	resp.Headers.Set("Content-Length", fmt.Sprintf("%d", len(body)))
	resp.Headers.Set("Connection", "close")
	return writeRawResponse(conn, resp, body)
}
