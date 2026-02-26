package intercept

import (
	"fmt"
	"net/http"
	"net/url"
	"sync"
	"time"

	"github.com/google/uuid"
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

// InterceptAction represents the action to take on an intercepted request,
// including optional modification parameters for modify_and_forward.
type InterceptAction struct {
	// Type is the action type (release, modify_and_forward, or drop).
	Type ActionType

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
}

// InterceptedRequest represents a request that has been intercepted and is waiting
// for an action from the AI agent.
type InterceptedRequest struct {
	// ID is the unique identifier for this intercepted request.
	ID string
	// Method is the HTTP method of the intercepted request.
	Method string
	// URL is the request URL.
	URL *url.URL
	// Headers are the request headers.
	Headers http.Header
	// Body is the request body.
	Body []byte
	// Timestamp is when the request was intercepted.
	Timestamp time.Time
	// MatchedRules lists the IDs of the rules that matched this request.
	MatchedRules []string

	// actionCh receives the action to perform on this request.
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

// Enqueue adds a new intercepted request to the queue and returns its ID
// along with a channel that will receive the action to perform.
// The caller should block on the returned channel until an action is received.
//
// If the queue has reached its maxItems limit, the request is immediately
// auto-released (ActionRelease is sent on the channel) to prevent memory
// exhaustion from unbounded queue growth.
func (q *Queue) Enqueue(method string, u *url.URL, headers http.Header, body []byte, matchedRules []string) (string, <-chan InterceptAction) {
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
	headersCopy := make(http.Header)
	for k, vs := range headers {
		cp := make([]string, len(vs))
		copy(cp, vs)
		headersCopy[k] = cp
	}

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
		Method:       method,
		URL:          urlCopy,
		Headers:      headersCopy,
		Body:         bodyCopy,
		Timestamp:    time.Now(),
		MatchedRules: rulesCopy,
		actionCh:     actionCh,
	}

	q.mu.Lock()
	// Re-check under lock in case another goroutine filled the queue
	// between our capacity check and now.
	if q.maxItems > 0 && len(q.items) >= q.maxItems {
		q.mu.Unlock()
		actionCh <- InterceptAction{Type: ActionRelease}
		return id, actionCh
	}
	q.items[id] = item
	q.mu.Unlock()

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
func (q *Queue) List() []*InterceptedRequest {
	q.mu.Lock()
	defer q.mu.Unlock()

	if len(q.items) == 0 {
		return nil
	}

	result := make([]*InterceptedRequest, 0, len(q.items))
	for _, item := range q.items {
		result = append(result, item)
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

	// Send action to the channel. This is non-blocking because the channel
	// has a buffer of 1.
	item.actionCh <- action
	return nil
}

// Remove removes a request from the queue without sending an action.
// This is used for cleanup when a request times out.
func (q *Queue) Remove(id string) {
	q.mu.Lock()
	delete(q.items, id)
	q.mu.Unlock()
}

// Clear removes all requests from the queue.
func (q *Queue) Clear() {
	q.mu.Lock()
	defer q.mu.Unlock()
	q.items = make(map[string]*InterceptedRequest)
}
