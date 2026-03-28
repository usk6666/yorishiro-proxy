package intercept

import (
	"fmt"
	"log/slog"
	"net/url"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/usk6666/yorishiro-proxy/internal/protocol/http/parser"
)

// ActionType specifies the action to take on an intercepted request.
type ActionType int

const (
	// ActionRelease forwards the request as-is to the upstream server.
	ActionRelease ActionType = iota
	// ActionModifyAndForward forwards the request with modifications.
	ActionModifyAndForward
	// ActionDrop discards the request and returns an error to the client.
	ActionDrop
)

// TimeoutBehavior specifies what happens when an intercepted request times out.
type TimeoutBehavior string

const (
	// TimeoutAutoRelease automatically forwards the request on timeout.
	TimeoutAutoRelease TimeoutBehavior = "auto_release"
	// TimeoutAutoDrop automatically drops the request on timeout.
	TimeoutAutoDrop TimeoutBehavior = "auto_drop"
)

// DefaultInterceptTimeout is the default timeout for blocked requests.
const DefaultInterceptTimeout = 5 * time.Minute

// DefaultMaxQueueItems is the default maximum number of items the queue
// can hold. When exceeded, new requests are auto-released to prevent
// memory exhaustion (CWE-770).
const DefaultMaxQueueItems = 100

// InterceptPhase specifies whether an intercepted item is a request or response.
type InterceptPhase string

const (
	// PhaseRequest indicates the intercepted item is a request (pre-send).
	PhaseRequest InterceptPhase = "request"
	// PhaseResponse indicates the intercepted item is a response (post-receive).
	PhaseResponse InterceptPhase = "response"
	// PhaseWebSocketFrame indicates the intercepted item is a WebSocket frame.
	PhaseWebSocketFrame InterceptPhase = "websocket_frame"
)

// ReleaseMode specifies whether the release/modify_and_forward action uses
// structured (L7) modifications or raw bytes forwarding.
type ReleaseMode string

const (
	// ModeStructured uses the traditional L7 structured modifications
	// (override_method, override_headers, override_body, etc.).
	// This is the default mode for backward compatibility.
	ModeStructured ReleaseMode = "structured"
	// ModeRaw sends raw bytes directly to the upstream connection,
	// bypassing L7 serialization. The raw bytes are forwarded as-is.
	ModeRaw ReleaseMode = "raw"
)

// MaxRawBytesSize is the maximum allowed size for raw bytes in an intercept
// action. This prevents memory exhaustion from excessively large payloads
// (CWE-770). 10 MiB is generous for most HTTP traffic while preventing abuse.
const MaxRawBytesSize = 10 * 1024 * 1024 // 10 MiB

// InterceptAction represents the action to take on an intercepted request or response,
// including optional modification parameters for modify_and_forward.
type InterceptAction struct {
	// Type is the action type (release, modify_and_forward, or drop).
	Type ActionType

	// Mode specifies the forwarding mode: "structured" (default) or "raw".
	// When Mode is "raw", all L7 modification fields are ignored and
	// RawOverride is sent directly to the upstream connection.
	Mode ReleaseMode

	// RawOverride contains the raw bytes to send when Mode is "raw".
	// This bypasses L7 serialization and is written directly to the connection.
	RawOverride []byte

	// --- Request modification fields (modify_and_forward, phase=request, mode=structured) ---

	// OverrideMethod overrides the HTTP method (modify_and_forward only).
	OverrideMethod string
	// OverrideURL overrides the request URL (modify_and_forward only).
	OverrideURL string
	// OverrideHeaders replaces specific header values (modify_and_forward only).
	OverrideHeaders map[string]string
	// AddHeaders appends header values (modify_and_forward only).
	AddHeaders map[string]string
	// RemoveHeaders removes specific headers (modify_and_forward only).
	RemoveHeaders []string
	// OverrideBody replaces the entire request body (modify_and_forward only).
	OverrideBody *string
	// OverrideBodyBase64 replaces the body with Base64-decoded content (modify_and_forward only).
	OverrideBodyBase64 *string

	// --- Response modification fields (modify_and_forward, phase=response, mode=structured) ---

	// OverrideStatus overrides the HTTP status code (response modify_and_forward only).
	OverrideStatus int
	// OverrideResponseHeaders replaces specific response header values.
	OverrideResponseHeaders map[string]string
	// AddResponseHeaders appends response header values.
	AddResponseHeaders map[string]string
	// RemoveResponseHeaders removes specific response headers.
	RemoveResponseHeaders []string
	// OverrideResponseBody replaces the entire response body.
	OverrideResponseBody *string
}

// InterceptedRequest represents a request or response that has been intercepted
// and is waiting for an action from the AI agent.
type InterceptedRequest struct {
	// ID is the unique identifier for this intercepted item.
	ID string
	// Phase indicates whether this is a request or response intercept.
	Phase InterceptPhase
	// Method is the HTTP method of the intercepted request.
	Method string
	// URL is the request URL.
	URL *url.URL
	// Headers are the request headers (phase=request) or response headers (phase=response).
	Headers parser.RawHeaders
	// Body is the request body (phase=request) or response body (phase=response).
	Body []byte
	// StatusCode is the HTTP status code (only set for phase=response).
	StatusCode int
	// Timestamp is when the item was intercepted.
	Timestamp time.Time
	// MatchedRules lists the IDs of the rules that matched.
	MatchedRules []string

	// RawBytes holds the raw bytes of the intercepted request or response,
	// captured before L7 parsing. This allows AI agents to view and edit
	// the exact bytes on the wire. May be nil if raw capture is not available
	// for the protocol or connection.
	RawBytes []byte

	// Metadata holds protocol-specific metadata for the intercepted item.
	// For gRPC requests, this includes "grpc_content_type", "grpc_encoding",
	// "grpc_compressed", and "original_frames" to enable proper re-encoding
	// on modify_and_forward.
	Metadata map[string]string

	// --- WebSocket frame metadata (phase=websocket_frame only) ---

	// WSOpcode is the WebSocket frame opcode (e.g. 0x1 for text, 0x2 for binary).
	WSOpcode int
	// WSDirection is the frame direction: "client_to_server" or "server_to_client".
	WSDirection string
	// WSFlowID is the WebSocket flow ID this frame belongs to.
	WSFlowID string
	// WSUpgradeURL is the URL from the original WebSocket upgrade request.
	WSUpgradeURL string
	// WSSequence is the frame sequence number within the WebSocket connection.
	WSSequence int64

	// actionCh receives the action to perform on this intercepted item.
	// It is buffered with capacity 1 to prevent goroutine leaks on timeout.
	actionCh chan InterceptAction
}

// Queue manages intercepted requests that are waiting for AI agent actions.
// It is safe for concurrent use.
type Queue struct {
	mu       sync.Mutex
	items    map[string]*InterceptedRequest
	timeout  time.Duration
	behavior TimeoutBehavior
	maxItems int
}

// NewQueue creates a new Queue with default timeout, auto_release behavior,
// and a default max queue size of DefaultMaxQueueItems.
func NewQueue() *Queue {
	return &Queue{
		items:    make(map[string]*InterceptedRequest),
		timeout:  DefaultInterceptTimeout,
		behavior: TimeoutAutoRelease,
		maxItems: DefaultMaxQueueItems,
	}
}

// SetTimeout sets the timeout duration for blocked requests.
func (q *Queue) SetTimeout(d time.Duration) {
	q.mu.Lock()
	defer q.mu.Unlock()
	q.timeout = d
}

// Timeout returns the current timeout duration.
func (q *Queue) Timeout() time.Duration {
	q.mu.Lock()
	defer q.mu.Unlock()
	return q.timeout
}

// SetTimeoutBehavior sets what happens when blocked requests time out.
func (q *Queue) SetTimeoutBehavior(b TimeoutBehavior) {
	q.mu.Lock()
	defer q.mu.Unlock()
	q.behavior = b
}

// TimeoutBehaviorValue returns the current timeout behavior.
func (q *Queue) TimeoutBehaviorValue() TimeoutBehavior {
	q.mu.Lock()
	defer q.mu.Unlock()
	return q.behavior
}

// SetMaxItems sets the maximum number of items the queue can hold.
// When the queue is full, new requests are auto-released immediately
// to prevent memory exhaustion. A value of 0 or negative means unlimited.
func (q *Queue) SetMaxItems(n int) {
	q.mu.Lock()
	defer q.mu.Unlock()
	q.maxItems = n
}

// MaxItems returns the current maximum queue size.
func (q *Queue) MaxItems() int {
	q.mu.Lock()
	defer q.mu.Unlock()
	return q.maxItems
}

// applyEnqueueOpts copies RawBytes and Metadata from the first element of
// opts into the item before it is inserted into the queue map. This ensures
// the fields are visible the moment the item appears in List().
// Only the first EnqueueOpts is used; additional elements are ignored.
// RawBytes exceeding MaxRawBytesSize are silently discarded (same policy
// as SetRawBytes).
func applyEnqueueOpts(item *InterceptedRequest, opts []EnqueueOpts) {
	if len(opts) == 0 {
		return
	}
	o := opts[0]
	if len(o.RawBytes) > 0 && len(o.RawBytes) <= MaxRawBytesSize {
		cp := make([]byte, len(o.RawBytes))
		copy(cp, o.RawBytes)
		item.RawBytes = cp
	}
	if len(o.Metadata) > 0 {
		cp := make(map[string]string, len(o.Metadata))
		for k, v := range o.Metadata {
			cp[k] = v
		}
		item.Metadata = cp
	}
}

// EnqueueOpts carries optional fields that must be atomically visible when
// an item first appears in the queue. Without this, callers that set
// RawBytes or Metadata via separate SetRawBytes/SetMetadata calls after
// Enqueue create a race: another goroutine can List() the item before the
// metadata is attached.
type EnqueueOpts struct {
	// RawBytes holds the raw bytes of the intercepted request or response.
	RawBytes []byte
	// Metadata holds protocol-specific metadata (e.g. gRPC encoding info).
	Metadata map[string]string
}

// Enqueue adds a new intercepted request to the queue and returns its ID
// along with a channel that will receive the action to perform.
// The caller should block on the returned channel until an action is received.
//
// If the queue has reached its maxItems limit, the request is immediately
// auto-released (ActionRelease is sent on the channel) to prevent memory
// exhaustion from unbounded queue growth.
//
// An optional EnqueueOpts may be provided to atomically attach RawBytes
// and/or Metadata at enqueue time, avoiding the race window that exists
// when using SetRawBytes/SetMetadata after Enqueue.
func (q *Queue) Enqueue(method string, u *url.URL, headers parser.RawHeaders, body []byte, matchedRules []string, opts ...EnqueueOpts) (string, <-chan InterceptAction) {
	id := uuid.New().String()
	actionCh := make(chan InterceptAction, 1)

	// Check queue capacity under lock before doing expensive deep-copies.
	q.mu.Lock()
	if q.maxItems > 0 && len(q.items) >= q.maxItems {
		q.mu.Unlock()
		// Queue is full — auto-release immediately to prevent memory exhaustion.
		actionCh <- InterceptAction{Type: ActionRelease}
		return id, actionCh
	}
	q.mu.Unlock()

	// Deep-copy URL to avoid races.
	var urlCopy *url.URL
	if u != nil {
		tmp := *u
		urlCopy = &tmp
	}

	// Deep-copy headers.
	headersCopy := headers.Clone()

	// Copy body.
	var bodyCopy []byte
	if len(body) > 0 {
		bodyCopy = make([]byte, len(body))
		copy(bodyCopy, body)
	}

	// Copy matched rules.
	var rulesCopy []string
	if len(matchedRules) > 0 {
		rulesCopy = make([]string, len(matchedRules))
		copy(rulesCopy, matchedRules)
	}

	item := &InterceptedRequest{
		ID:           id,
		Phase:        PhaseRequest,
		Method:       method,
		URL:          urlCopy,
		Headers:      headersCopy,
		Body:         bodyCopy,
		Timestamp:    time.Now(),
		MatchedRules: rulesCopy,
		actionCh:     actionCh,
	}

	// Apply optional RawBytes/Metadata before inserting into the map,
	// so the item is fully populated when it becomes visible via List().
	applyEnqueueOpts(item, opts)

	q.mu.Lock()
	// Re-check under lock in case another goroutine filled the queue
	// between our capacity check and now.
	if q.maxItems > 0 && len(q.items) >= q.maxItems {
		q.mu.Unlock()
		slog.Debug("intercept queue full, auto-releasing request",
			slog.String("intercept_id", id),
			slog.String("method", method),
		)
		actionCh <- InterceptAction{Type: ActionRelease}
		return id, actionCh
	}
	q.items[id] = item
	q.mu.Unlock()

	slog.Debug("request held in intercept queue",
		slog.String("intercept_id", id),
		slog.String("method", method),
		slog.String("url", urlString(urlCopy)),
		slog.Any("matched_rules", rulesCopy),
	)

	return id, actionCh
}

// EnqueueResponse adds a new intercepted response to the queue and returns its ID
// along with a channel that will receive the action to perform.
// The method and reqURL parameters identify the original request that produced
// this response. statusCode, headers, and body describe the response itself.
//
// If the queue has reached its maxItems limit, the response is immediately
// auto-released.
func (q *Queue) EnqueueResponse(method string, reqURL *url.URL, statusCode int, headers parser.RawHeaders, body []byte, matchedRules []string, opts ...EnqueueOpts) (string, <-chan InterceptAction) {
	id := uuid.New().String()
	actionCh := make(chan InterceptAction, 1)

	// Check queue capacity under lock.
	q.mu.Lock()
	if q.maxItems > 0 && len(q.items) >= q.maxItems {
		q.mu.Unlock()
		actionCh <- InterceptAction{Type: ActionRelease}
		return id, actionCh
	}
	q.mu.Unlock()

	// Deep-copy URL.
	var urlCopy *url.URL
	if reqURL != nil {
		tmp := *reqURL
		urlCopy = &tmp
	}

	// Deep-copy headers.
	headersCopy := headers.Clone()

	// Copy body.
	var bodyCopy []byte
	if len(body) > 0 {
		bodyCopy = make([]byte, len(body))
		copy(bodyCopy, body)
	}

	// Copy matched rules.
	var rulesCopy []string
	if len(matchedRules) > 0 {
		rulesCopy = make([]string, len(matchedRules))
		copy(rulesCopy, matchedRules)
	}

	item := &InterceptedRequest{
		ID:           id,
		Phase:        PhaseResponse,
		Method:       method,
		URL:          urlCopy,
		Headers:      headersCopy,
		Body:         bodyCopy,
		StatusCode:   statusCode,
		Timestamp:    time.Now(),
		MatchedRules: rulesCopy,
		actionCh:     actionCh,
	}

	applyEnqueueOpts(item, opts)

	q.mu.Lock()
	if q.maxItems > 0 && len(q.items) >= q.maxItems {
		q.mu.Unlock()
		slog.Debug("intercept queue full, auto-releasing response",
			slog.String("intercept_id", id),
			slog.Int("status_code", statusCode),
		)
		actionCh <- InterceptAction{Type: ActionRelease}
		return id, actionCh
	}
	q.items[id] = item
	q.mu.Unlock()

	slog.Debug("response held in intercept queue",
		slog.String("intercept_id", id),
		slog.Int("status_code", statusCode),
		slog.String("url", urlString(urlCopy)),
		slog.Any("matched_rules", rulesCopy),
	)

	return id, actionCh
}

// EnqueueWebSocketFrame adds a new intercepted WebSocket frame to the queue
// and returns its ID along with a channel that will receive the action to perform.
// The caller should block on the returned channel until an action is received.
//
// If the queue has reached its maxItems limit, the frame is immediately
// auto-released.
func (q *Queue) EnqueueWebSocketFrame(opcode int, direction, flowID, upgradeURL string, sequence int64, payload []byte, matchedRules []string, opts ...EnqueueOpts) (string, <-chan InterceptAction) {
	id := uuid.New().String()
	actionCh := make(chan InterceptAction, 1)

	// Check queue capacity under lock.
	q.mu.Lock()
	if q.maxItems > 0 && len(q.items) >= q.maxItems {
		q.mu.Unlock()
		actionCh <- InterceptAction{Type: ActionRelease}
		return id, actionCh
	}
	q.mu.Unlock()

	// Copy payload.
	var payloadCopy []byte
	if len(payload) > 0 {
		payloadCopy = make([]byte, len(payload))
		copy(payloadCopy, payload)
	}

	// Copy matched rules.
	var rulesCopy []string
	if len(matchedRules) > 0 {
		rulesCopy = make([]string, len(matchedRules))
		copy(rulesCopy, matchedRules)
	}

	item := &InterceptedRequest{
		ID:           id,
		Phase:        PhaseWebSocketFrame,
		Body:         payloadCopy,
		Timestamp:    time.Now(),
		MatchedRules: rulesCopy,
		WSOpcode:     opcode,
		WSDirection:  direction,
		WSFlowID:     flowID,
		WSUpgradeURL: upgradeURL,
		WSSequence:   sequence,
		actionCh:     actionCh,
	}

	applyEnqueueOpts(item, opts)

	q.mu.Lock()
	if q.maxItems > 0 && len(q.items) >= q.maxItems {
		q.mu.Unlock()
		slog.Debug("intercept queue full, auto-releasing websocket frame",
			slog.String("intercept_id", id),
			slog.String("flow_id", flowID),
		)
		actionCh <- InterceptAction{Type: ActionRelease}
		return id, actionCh
	}
	q.items[id] = item
	q.mu.Unlock()

	slog.Debug("websocket frame held in intercept queue",
		slog.String("intercept_id", id),
		slog.String("direction", direction),
		slog.String("flow_id", flowID),
		slog.Int64("sequence", sequence),
		slog.Any("matched_rules", rulesCopy),
	)

	return id, actionCh
}

// Get returns the intercepted request with the given ID, or an error if not found.
func (q *Queue) Get(id string) (*InterceptedRequest, error) {
	q.mu.Lock()
	defer q.mu.Unlock()

	item, ok := q.items[id]
	if !ok {
		return nil, fmt.Errorf("intercepted request %q not found", id)
	}
	return item, nil
}

// List returns all currently intercepted (blocked) requests.
// The returned items are deep copies — callers may read fields without
// holding the queue lock. Mutations to the copies do not affect the
// queue's internal state.
func (q *Queue) List() []*InterceptedRequest {
	q.mu.Lock()
	defer q.mu.Unlock()

	if len(q.items) == 0 {
		return nil
	}

	result := make([]*InterceptedRequest, 0, len(q.items))
	for _, item := range q.items {
		cp := *item // shallow value copy
		if item.Metadata != nil {
			cp.Metadata = make(map[string]string, len(item.Metadata))
			for k, v := range item.Metadata {
				cp.Metadata[k] = v
			}
		}
		if item.Headers != nil {
			cp.Headers = item.Headers.Clone()
		}
		// RawBytes, Body, MatchedRules are append-only or read-only after
		// enqueue, so shallow copies are safe.
		result = append(result, &cp)
	}
	return result
}

// Len returns the number of items currently in the queue.
func (q *Queue) Len() int {
	q.mu.Lock()
	defer q.mu.Unlock()
	return len(q.items)
}

// Respond sends an action for the intercepted request with the given ID,
// unblocking the handler waiting on it. The request is removed from the queue.
// Returns an error if the request is not found.
func (q *Queue) Respond(id string, action InterceptAction) error {
	q.mu.Lock()
	item, ok := q.items[id]
	if !ok {
		q.mu.Unlock()
		return fmt.Errorf("intercepted request %q not found", id)
	}
	delete(q.items, id)
	q.mu.Unlock()

	slog.Debug("intercept queue item released",
		slog.String("intercept_id", id),
		slog.String("phase", string(item.Phase)),
		slog.String("action", actionTypeString(action.Type)),
		slog.String("mode", string(action.EffectiveMode())),
	)

	// Send action to the channel. This is non-blocking because the channel
	// has a buffer of 1.
	item.actionCh <- action
	return nil
}

// actionTypeString returns a human-readable string for an ActionType.
func actionTypeString(a ActionType) string {
	switch a {
	case ActionRelease:
		return "release"
	case ActionModifyAndForward:
		return "modify_and_forward"
	case ActionDrop:
		return "drop"
	default:
		return "unknown"
	}
}

// Remove removes a request from the queue without sending an action.
// This is used for cleanup when a request times out.
func (q *Queue) Remove(id string) {
	q.mu.Lock()
	delete(q.items, id)
	q.mu.Unlock()
}

// SetMetadata attaches protocol-specific metadata to an already-enqueued
// intercepted item. For gRPC requests, this includes encoding and compression
// information needed for re-encoding on modify_and_forward.
// Returns an error if the item is not found.
func (q *Queue) SetMetadata(id string, metadata map[string]string) error {
	q.mu.Lock()
	defer q.mu.Unlock()

	item, ok := q.items[id]
	if !ok {
		return fmt.Errorf("intercepted request %q not found", id)
	}

	// Deep copy the metadata map for consistency with SetRawBytes.
	cp := make(map[string]string, len(metadata))
	for k, v := range metadata {
		cp[k] = v
	}
	item.Metadata = cp

	slog.Debug("metadata attached to intercept queue item",
		slog.String("intercept_id", id),
		slog.Int("metadata_keys", len(metadata)),
	)
	return nil
}

// SetRawBytes attaches raw bytes to an already-enqueued intercepted item.
// This is used by protocol handlers that capture raw bytes after enqueuing
// the L7-parsed request. Returns an error if the item is not found or if
// the raw bytes exceed MaxRawBytesSize.
func (q *Queue) SetRawBytes(id string, rawBytes []byte) error {
	if len(rawBytes) > MaxRawBytesSize {
		return fmt.Errorf("raw bytes size %d exceeds maximum %d", len(rawBytes), MaxRawBytesSize)
	}

	q.mu.Lock()
	defer q.mu.Unlock()

	item, ok := q.items[id]
	if !ok {
		return fmt.Errorf("intercepted request %q not found", id)
	}

	if len(rawBytes) > 0 {
		cp := make([]byte, len(rawBytes))
		copy(cp, rawBytes)
		item.RawBytes = cp
	}

	slog.Debug("raw bytes attached to intercept queue item",
		slog.String("intercept_id", id),
		slog.Int("raw_bytes_size", len(rawBytes)),
	)
	return nil
}

// Clear removes all requests from the queue.
func (q *Queue) Clear() {
	q.mu.Lock()
	defer q.mu.Unlock()
	q.items = make(map[string]*InterceptedRequest)
}

// IsRawMode returns true if the action specifies raw byte forwarding mode.
func (a InterceptAction) IsRawMode() bool {
	return a.Mode == ModeRaw
}

// EffectiveMode returns the release mode, defaulting to ModeStructured
// when Mode is empty (backward compatibility).
func (a InterceptAction) EffectiveMode() ReleaseMode {
	if a.Mode == "" {
		return ModeStructured
	}
	return a.Mode
}

// ValidateRawOverride checks that the raw override bytes are within
// the allowed size limit. Returns an error if the payload exceeds MaxRawBytesSize.
func ValidateRawOverride(raw []byte) error {
	if len(raw) > MaxRawBytesSize {
		return fmt.Errorf("raw bytes size %d exceeds maximum %d", len(raw), MaxRawBytesSize)
	}
	return nil
}
