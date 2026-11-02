package connector

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"strconv"

	"github.com/usk6666/yorishiro-proxy/internal/layer/http1"
)

// ForwardRouter switches an explicit plain-HTTP forward-proxy connection's
// upstream to the host a later keep-alive request names (USK-1410).
//
// The forward handler dials the first request's target. Each later
// request's target is resolved by the client Layer with the same rule
// (resolveForwardTarget) and stamped as its TargetHost; when it differs
// from the connection's current upstream, the session's HTTP/1 upstream
// chain calls Retarget, which runs the first-request gate again for the
// new target — scope, live-connection registration, rate limit — and dials
// it. A refusal is a *ForwardRefusal carrying the same response the gate
// answers a refused first request with.
//
// One router serves every connection of a forward listener; it holds only
// configuration. Requests on one connection are serial (the client Layer
// parses the next request only after the previous exchange ended), so no
// two Retargets of one connection overlap.
type ForwardRouter struct {
	buildCfg    *BuildConfig
	scope       *TargetScope
	rateLimiter *RateLimiter
	logger      *slog.Logger
}

// newForwardRouter returns the router for a forward handler's connections.
func newForwardRouter(cfg HTTP1ForwardHandlerConfig, logger *slog.Logger) *ForwardRouter {
	return &ForwardRouter{
		buildCfg:    cfg.BuildCfg,
		scope:       cfg.Scope,
		rateLimiter: cfg.RateLimiter,
		logger:      logger,
	}
}

// ForwardRefusal is the error Retarget returns when the switch to a new
// target is refused or fails before any byte reached it. Response is the
// complete response the client must get — the bytes the forward handler's
// first-request gate writes for the same outcome (Connection: close) —
// after which the client connection is closed.
type ForwardRefusal struct {
	// Target is the target the request named.
	Target string
	// Status is Response's status code: 400 (unusable target), 403
	// (scope), 429 (rate limit) or 502 (dial / upstream proxy failure).
	Status int
	// BlockedBy is the policy attribution ("target_scope" / "rate_limit");
	// empty for a failure that is not a policy refusal (400 / 502).
	BlockedBy string
	// Response is the exact response to write to the client.
	Response []byte
	// Tags are the audit tags of a policy refusal (via, target, reason
	// and, for a rate limit, the denial's rate_limit_* tags), as the
	// first-request gate records them. Nil for 400 / 502.
	Tags map[string]string
	// Err is the cause.
	Err error
}

// Error describes the refusal.
func (e *ForwardRefusal) Error() string {
	return fmt.Sprintf("connector: forward request to %s refused with %d: %v", e.Target, e.Status, e.Err)
}

// Unwrap returns the cause.
func (e *ForwardRefusal) Unwrap() error { return e.Err }

// Retarget runs the forward gate for target and returns a fresh upstream
// HTTP/1.x Layer connected to it. stale is the connection's current
// upstream Layer: the fresh one copies its envelope context template with
// TargetHost = target and the new socket's peer, so the Streams it serves
// record target and its address. generation labels the Layer like a redial
// step (RedialConnIDLabel). ctx must be the connection's context (it
// carries the live-connection handle and the conn ID).
//
// Gate order mirrors NewHTTP1ForwardHandler: scope check, live-connection
// re-registration (LiveConnHandle.Retarget — Reconcile judges target from
// then on), rate limit (one token per switch), then the dial through
// dialPlainUpstream (upstream proxy, per-target rotation, fail-closed on a
// rotation error). Every failure is a *ForwardRefusal; the stale Layer is
// left to the caller.
func (r *ForwardRouter) Retarget(ctx context.Context, stale *http1.Layer, target string, generation int) (*http1.Layer, error) {
	if stale == nil {
		return nil, fmt.Errorf("connector: ForwardRouter.Retarget: stale is nil")
	}
	logger := LoggerFromContext(ctx, r.logger).With("target", target, "via", "http1-forward")

	if _, _, err := SplitTargetHostPort(target); err != nil {
		logger.Debug("plain HTTP: invalid retarget", "error", err)
		return nil, &ForwardRefusal{Target: target, Status: 400, Err: err,
			Response: forwardErrorResponse(400, "Bad Request", "yorishiro-proxy: invalid forward-proxy target")}
	}

	admit := func() (bool, string) {
		allowed, reason, _ := forwardScopeCheck(r.scope, target)
		return allowed, reason
	}
	if allowed, reason := admit(); !allowed {
		logger.Info("plain HTTP target blocked by scope", "reason", reason)
		return nil, r.scopeRefusal(ctx, target, nonEmptyScopeReason(reason))
	}
	if err := LiveConnFromContext(ctx).Retarget(target, admit, nil); err != nil {
		logger.Info("target blocked by scope (policy changed during admission)", "error", err)
		return nil, r.scopeRefusal(ctx, target, AdmissionRaceReason(err))
	}

	if r.rateLimiter != nil {
		host, _, _ := net.SplitHostPort(target)
		if denial := r.rateLimiter.Check(host); denial != nil {
			logger.Info("plain HTTP target blocked by rate limit",
				"limit_type", denial.LimitType,
				"effective_rps", denial.EffectiveRPS)
			reason := denial.LimitType + " limit " + strconv.FormatFloat(denial.EffectiveRPS, 'g', -1, 64) + " rps"
			tags := newGateRefusal(ctx, "http1-forward", target, nil, GateRefusalBlockedByRateLimit, reason).Tags
			for k, v := range denial.Tags() {
				tags[k] = v
			}
			return nil, &ForwardRefusal{Target: target, Status: 429, BlockedBy: GateRefusalBlockedByRateLimit,
				Response: RateLimitRefusalResponse(), Tags: tags, Err: errors.New(reason)}
		}
	}

	conn, err := dialPlainUpstream(ctx, target, r.buildCfg)
	if err != nil {
		detail := "yorishiro-proxy: upstream dial failed"
		if errors.Is(err, errUpstreamProxyRotation) {
			logger.Warn("plain HTTP upstream proxy rotation failed; failing closed", "error", err)
			detail = "yorishiro-proxy: upstream proxy rotation failed"
		} else {
			logger.Debug("plain HTTP upstream dial failed", "error", err)
		}
		return nil, &ForwardRefusal{Target: target, Status: 502, Err: err,
			Response: forwardErrorResponse(502, "Bad Gateway", detail)}
	}

	envCtx := WithUpstreamPeer(stale.EnvelopeContextTemplate(), conn)
	envCtx.TargetHost = target
	return newUpstreamH1Layer(conn, redialConnIDLabel(envCtx.ConnID, generation), stale.Scheme(), envCtx, r.buildCfg), nil
}

// scopeRefusal is the 403 a scope-refused switch answers, with the audit
// tags the first-request gate records for a scope refusal.
func (r *ForwardRouter) scopeRefusal(ctx context.Context, target, reason string) *ForwardRefusal {
	return &ForwardRefusal{
		Target:    target,
		Status:    403,
		BlockedBy: GateRefusalBlockedByTargetScope,
		Response:  forwardErrorResponse(403, "Forbidden", "yorishiro-proxy: target blocked by scope"),
		Tags:      newGateRefusal(ctx, "http1-forward", target, nil, GateRefusalBlockedByTargetScope, reason).Tags,
		Err:       errors.New(reason),
	}
}
