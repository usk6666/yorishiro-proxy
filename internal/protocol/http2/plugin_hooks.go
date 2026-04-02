package http2

import (
	"context"
	"fmt"
	"log/slog"
	"strings"

	"github.com/usk6666/yorishiro-proxy/internal/plugin"
	"github.com/usk6666/yorishiro-proxy/internal/protocol/http2/hpack"
	"github.com/usk6666/yorishiro-proxy/internal/protocol/httputil"
)

// dispatchOnReceiveFromClient dispatches the on_receive_from_client hook.
// It may return ActionDrop (return 502) or ActionRespond (send custom response).
// Returns the (possibly modified) h2Request, body, and a boolean indicating the
// request was terminated (caller should return early).
// The txCtx is a mutable dict shared across all hooks within the same transaction.
// rawFrames contains the raw HTTP/2 frame bytes received from the client,
// which are injected into the hook data as an optional "raw_frames" field.
func (h *Handler) dispatchOnReceiveFromClient(ctx context.Context, w h2ResponseWriter, h2req *h2Request, body []byte, connInfo *plugin.ConnInfo, txCtx map[string]any, rawFrames [][]byte, logger *slog.Logger) (*h2Request, []byte, bool) {
	if h.pluginEngine == nil {
		return h2req, body, false
	}

	data := plugin.H2RequestToMap(h2req.Method, h2req.Scheme, h2req.Authority, h2req.Path, h2req.RegularHeaders(), body, connInfo, "h2")
	plugin.InjectRawFrames(data, rawFrames)
	plugin.InjectTxCtx(data, txCtx)

	result, err := h.pluginEngine.Dispatch(ctx, plugin.HookOnReceiveFromClient, data)
	if err != nil {
		logger.Warn("plugin on_receive_from_client error", "error", err)
		return h2req, body, false
	}
	plugin.ExtractTxCtx(result, txCtx)
	if result == nil {
		return h2req, body, false
	}

	switch result.Action {
	case plugin.ActionDrop:
		writeErrorResponse(w, httputil.StatusBadGateway)
		logger.Info("plugin dropped request", "hook", "on_receive_from_client",
			"method", h2req.Method, "url", h2req.Scheme+"://"+h2req.Authority+h2req.Path)
		return h2req, body, true

	case plugin.ActionRespond:
		writePluginRespondResponse(w, result.ResponseData, logger)
		logger.Info("plugin responded to request", "hook", "on_receive_from_client",
			"method", h2req.Method, "url", h2req.Scheme+"://"+h2req.Authority+h2req.Path)
		return h2req, body, true

	case plugin.ActionContinue:
		if result.Data != nil {
			newMethod, newScheme, newAuthority, newPath, newHeaders, newBody, applyErr := plugin.ApplyH2RequestChanges(
				h2req.Method, h2req.Scheme, h2req.Authority, h2req.Path,
				h2req.RegularHeaders(), result.Data,
			)
			if applyErr != nil {
				logger.Warn("plugin on_receive_from_client apply changes failed", "error", applyErr)
				return h2req, body, false
			}
			applyH2RequestFields(h2req, newMethod, newScheme, newAuthority, newPath, newHeaders)
			if newBody != nil {
				body = newBody
			}
		}
	}

	return h2req, body, false
}

// dispatchOnBeforeSendToServer dispatches the on_before_send_to_server hook.
// Returns the (possibly modified) h2Request and body.
// The txCtx is a mutable dict shared across all hooks within the same transaction.
// rawFrames contains the raw HTTP/2 frame bytes received from the client,
// which are injected into the hook data as an optional "raw_frames" field.
func (h *Handler) dispatchOnBeforeSendToServer(ctx context.Context, h2req *h2Request, body []byte, connInfo *plugin.ConnInfo, txCtx map[string]any, rawFrames [][]byte, logger *slog.Logger) (*h2Request, []byte) {
	if h.pluginEngine == nil {
		return h2req, body
	}

	data := plugin.H2RequestToMap(h2req.Method, h2req.Scheme, h2req.Authority, h2req.Path, h2req.RegularHeaders(), body, connInfo, "h2")
	plugin.InjectRawFrames(data, rawFrames)
	plugin.InjectTxCtx(data, txCtx)

	result, err := h.pluginEngine.Dispatch(ctx, plugin.HookOnBeforeSendToServer, data)
	if err != nil {
		logger.Warn("plugin on_before_send_to_server error", "error", err)
		return h2req, body
	}
	plugin.ExtractTxCtx(result, txCtx)
	if result == nil || result.Data == nil {
		return h2req, body
	}

	newMethod, newScheme, newAuthority, newPath, newHeaders, newBody, applyErr := plugin.ApplyH2RequestChanges(
		h2req.Method, h2req.Scheme, h2req.Authority, h2req.Path,
		h2req.RegularHeaders(), result.Data,
	)
	if applyErr != nil {
		logger.Warn("plugin on_before_send_to_server apply changes failed", "error", applyErr)
		return h2req, body
	}
	applyH2RequestFields(h2req, newMethod, newScheme, newAuthority, newPath, newHeaders)
	if newBody != nil {
		body = newBody
	}

	return h2req, body
}

// dispatchOnReceiveFromServerH2 dispatches the on_receive_from_server hook
// using hpack native types (no gohttp.Response).
func (h *Handler) dispatchOnReceiveFromServerH2(ctx context.Context, resp *h2Response, h2req *h2Request, connInfo *plugin.ConnInfo, txCtx map[string]any, rawFrames [][]byte, logger *slog.Logger) *h2Response {
	if h.pluginEngine == nil {
		return resp
	}

	var respTrailers []hpack.HeaderField
	if resp.Trailers != nil {
		respTrailers = resp.Trailers
	}

	data := plugin.H2ResponseToMap(
		resp.StatusCode, resp.Headers, respTrailers, resp.Body,
		h2req.Method, h2req.Scheme, h2req.Authority, h2req.Path,
		connInfo, "h2",
	)
	if rawFrames != nil {
		plugin.InjectRawFrames(data, rawFrames)
	}
	plugin.InjectTxCtx(data, txCtx)

	result, err := h.pluginEngine.Dispatch(ctx, plugin.HookOnReceiveFromServer, data)
	if err != nil {
		logger.Warn("plugin on_receive_from_server error", "error", err)
		return resp
	}
	plugin.ExtractTxCtx(result, txCtx)
	if result == nil || result.Data == nil {
		return resp
	}

	newStatus, newHeaders, newTrailers, newBody, applyErr := plugin.ApplyH2ResponseChanges(
		resp.StatusCode, resp.Headers, respTrailers, result.Data,
	)
	if applyErr != nil {
		logger.Warn("plugin on_receive_from_server apply changes failed", "error", applyErr)
		return resp
	}
	resp.StatusCode = newStatus
	if !sameHpackSlice(resp.Headers, newHeaders) {
		resp.Headers = newHeaders
	}
	if newTrailers != nil {
		resp.Trailers = newTrailers
	}
	if newBody != nil {
		resp.Body = newBody
	}

	return resp
}

// dispatchOnBeforeSendToClientH2 dispatches the on_before_send_to_client hook
// using hpack native types (no gohttp.Response).
func (h *Handler) dispatchOnBeforeSendToClientH2(ctx context.Context, resp *h2Response, h2req *h2Request, connInfo *plugin.ConnInfo, txCtx map[string]any, rawFrames [][]byte, logger *slog.Logger) *h2Response {
	if h.pluginEngine == nil {
		return resp
	}

	var respTrailers []hpack.HeaderField
	if resp.Trailers != nil {
		respTrailers = resp.Trailers
	}

	data := plugin.H2ResponseToMap(
		resp.StatusCode, resp.Headers, respTrailers, resp.Body,
		h2req.Method, h2req.Scheme, h2req.Authority, h2req.Path,
		connInfo, "h2",
	)
	if rawFrames != nil {
		plugin.InjectRawFrames(data, rawFrames)
	}
	plugin.InjectTxCtx(data, txCtx)

	result, err := h.pluginEngine.Dispatch(ctx, plugin.HookOnBeforeSendToClient, data)
	if err != nil {
		logger.Warn("plugin on_before_send_to_client error", "error", err)
		return resp
	}
	plugin.ExtractTxCtx(result, txCtx)
	if result == nil || result.Data == nil {
		return resp
	}

	newStatus, newHeaders, newTrailers, newBody, applyErr := plugin.ApplyH2ResponseChanges(
		resp.StatusCode, resp.Headers, respTrailers, result.Data,
	)
	if applyErr != nil {
		logger.Warn("plugin on_before_send_to_client apply changes failed", "error", applyErr)
		return resp
	}
	resp.StatusCode = newStatus
	if !sameHpackSlice(resp.Headers, newHeaders) {
		resp.Headers = newHeaders
	}
	if newTrailers != nil {
		resp.Trailers = newTrailers
	}
	if newBody != nil {
		resp.Body = newBody
	}

	return resp
}

// writePluginRespondResponse writes a plugin ActionRespond response to the
// client. It filters hop-by-hop and duplicate content-length headers, then
// adds an authoritative content-length based on the actual body length.
func writePluginRespondResponse(w h2ResponseWriter, responseData map[string]any, logger *slog.Logger) {
	statusCode, pluginHeaders, respBody := plugin.BuildRespondResponse(responseData)
	var hpackHeaders []hpack.HeaderField
	for _, hdr := range pluginHeaders {
		// HTTP/2 requires lowercase header names (RFC 9113 section 8.2).
		name := strings.ToLower(hdr.Name)
		// Filter pseudo-headers (WriteHeaders injects :status),
		// hop-by-hop headers (RFC 9113 section 8.2.2), and plugin-provided
		// content-length (we add the authoritative value below).
		if strings.HasPrefix(name, ":") || isHopByHopHeader(name) || name == "content-length" {
			continue
		}
		hpackHeaders = append(hpackHeaders, hpack.HeaderField{Name: name, Value: hdr.Value})
	}
	// RFC 9110 section 6.4.1: 1xx, 204, 205, and 304 must not include a body.
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

// applyH2RequestFields updates the h2Request fields and rebuilds AllHeaders
// from pseudo-headers + regular headers.
func applyH2RequestFields(req *h2Request, method, scheme, authority, path string, regularHeaders []hpack.HeaderField) {
	req.Method = method
	req.Scheme = scheme
	req.Authority = authority
	req.Path = path

	// Rebuild AllHeaders: pseudo-headers first, then regular headers.
	// RFC 9113 §8.5: CONNECT requests MUST include only :method and :authority;
	// :scheme and :path MUST NOT be present (unless extended CONNECT per RFC 8441,
	// which provides a non-empty path).
	isConnect := strings.EqualFold(method, "CONNECT")

	allHeaders := make([]hpack.HeaderField, 0, 4+len(regularHeaders))
	allHeaders = append(allHeaders, hpack.HeaderField{Name: ":method", Value: method})
	if scheme != "" && !isConnect {
		allHeaders = append(allHeaders, hpack.HeaderField{Name: ":scheme", Value: scheme})
	}
	if authority != "" {
		allHeaders = append(allHeaders, hpack.HeaderField{Name: ":authority", Value: authority})
	}
	if !isConnect || path != "" {
		allHeaders = append(allHeaders, hpack.HeaderField{Name: ":path", Value: path})
	}
	allHeaders = append(allHeaders, regularHeaders...)
	req.AllHeaders = allHeaders
}

// sameHpackSlice reports whether a and b share the same backing array and length,
// i.e., b was returned unmodified from a function that received a.
func sameHpackSlice(a, b []hpack.HeaderField) bool {
	if len(a) != len(b) {
		return false
	}
	if len(a) == 0 {
		return true
	}
	return &a[0] == &b[0]
}
