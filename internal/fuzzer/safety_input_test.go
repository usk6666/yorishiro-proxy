package fuzzer

import (
	"context"
	"fmt"
	"github.com/usk6666/yorishiro-proxy/internal/exchange"
	"net/url"
	"strings"
	"testing"
	"time"
)

func TestExecuteFuzzCase_SafetyInputChecker_Blocks(t *testing.T) {
	testURL, _ := url.Parse("http://example.com/api")

	checker := func(body []byte, rawURL string, headers []exchange.KeyValue) error {
		if strings.Contains(string(body), "DROP TABLE") {
			return fmt.Errorf("blocked: destructive SQL")
		}
		return nil
	}

	recorder := &mockFlowRecorder{}
	httpDoer := &mockHTTPDoer{}
	engine := NewEngine(nil, recorder, &mockFuzzJobStore{}, httpDoer, "")

	baseData := &RequestData{
		Method:  "POST",
		URL:     testURL,
		Headers: map[string][]string{"Content-Type": {"text/plain"}},
		Body:    []byte("DROP TABLE users;"),
	}

	fc := FuzzCase{Index: 0, Payloads: map[string]string{}}

	result := engine.executeFuzzCase(
		context.Background(), baseData, nil, fc,
		"HTTP/1.x", 5*time.Second, "fuzz-1", nil, nil, checker,
	)

	if result.Error == "" {
		t.Fatal("expected safety filter error, got none")
	}
	if !strings.Contains(result.Error, "safety filter") {
		t.Errorf("error = %q, want containing 'safety filter'", result.Error)
	}
	if !strings.Contains(result.Error, "blocked: destructive SQL") {
		t.Errorf("error = %q, want containing 'blocked: destructive SQL'", result.Error)
	}
}

func TestExecuteFuzzCase_SafetyInputChecker_AllowsSafe(t *testing.T) {
	testURL, _ := url.Parse("http://example.com/api")

	checkerCalled := false
	checker := func(body []byte, rawURL string, headers []exchange.KeyValue) error {
		checkerCalled = true
		return nil
	}

	recorder := &mockFlowRecorder{}
	httpDoer := &mockHTTPDoer{}
	engine := NewEngine(nil, recorder, &mockFuzzJobStore{}, httpDoer, "")

	baseData := &RequestData{
		Method:  "POST",
		URL:     testURL,
		Headers: map[string][]string{"Content-Type": {"text/plain"}},
		Body:    []byte("SELECT * FROM users WHERE id = 1"),
	}

	fc := FuzzCase{Index: 0, Payloads: map[string]string{}}

	result := engine.executeFuzzCase(
		context.Background(), baseData, nil, fc,
		"HTTP/1.x", 5*time.Second, "fuzz-1", nil, nil, checker,
	)

	if !checkerCalled {
		t.Fatal("safety input checker was not called")
	}
	if result.Error != "" {
		t.Errorf("unexpected error: %s", result.Error)
	}
}

func TestExecuteFuzzCase_SafetyInputChecker_NilPassesThrough(t *testing.T) {
	testURL, _ := url.Parse("http://example.com/api")

	recorder := &mockFlowRecorder{}
	httpDoer := &mockHTTPDoer{}
	engine := NewEngine(nil, recorder, &mockFuzzJobStore{}, httpDoer, "")

	baseData := &RequestData{
		Method:  "POST",
		URL:     testURL,
		Headers: map[string][]string{},
		Body:    []byte("DROP TABLE users;"),
	}

	fc := FuzzCase{Index: 0, Payloads: map[string]string{}}

	// nil safety checker should allow everything.
	result := engine.executeFuzzCase(
		context.Background(), baseData, nil, fc,
		"HTTP/1.x", 5*time.Second, "fuzz-1", nil, nil, nil,
	)

	if result.Error != "" {
		t.Errorf("unexpected error with nil checker: %s", result.Error)
	}
}

func TestExecuteFuzzCaseWithHooks_SafetyInputChecker_Blocks(t *testing.T) {
	testURL, _ := url.Parse("http://example.com/api")

	checker := func(body []byte, rawURL string, headers []exchange.KeyValue) error {
		if strings.Contains(string(body), "DROP TABLE") {
			return fmt.Errorf("blocked: destructive SQL")
		}
		return nil
	}

	recorder := &mockFlowRecorder{}
	httpDoer := &mockHTTPDoer{}
	engine := NewEngine(nil, recorder, &mockFuzzJobStore{}, httpDoer, "")

	baseData := &RequestData{
		Method:  "POST",
		URL:     testURL,
		Headers: map[string][]string{},
		Body:    []byte("DROP TABLE users;"),
	}

	fc := FuzzCase{Index: 0, Payloads: map[string]string{}}

	// Test with nil hooks (delegates to executeFuzzCase).
	result := engine.executeFuzzCaseWithHooks(
		context.Background(), baseData, nil, fc,
		"HTTP/1.x", 5*time.Second, "fuzz-1", nil, nil, nil, nil, checker,
	)

	if result.Error == "" {
		t.Fatal("expected safety filter error, got none")
	}
	if !strings.Contains(result.Error, "safety filter") {
		t.Errorf("error = %q, want containing 'safety filter'", result.Error)
	}
}

func TestExecuteFuzzCase_SafetyInputChecker_AfterPositionApplication(t *testing.T) {
	// Verify that the safety checker sees the expanded payload, not the template.
	testURL, _ := url.Parse("http://example.com/api")

	var checkedBody string
	checker := func(body []byte, rawURL string, headers []exchange.KeyValue) error {
		checkedBody = string(body)
		if strings.Contains(string(body), "DROP TABLE") {
			return fmt.Errorf("blocked: destructive SQL")
		}
		return nil
	}

	recorder := &mockFlowRecorder{}
	httpDoer := &mockHTTPDoer{}
	engine := NewEngine(nil, recorder, &mockFuzzJobStore{}, httpDoer, "")

	baseData := &RequestData{
		Method:  "POST",
		URL:     testURL,
		Headers: map[string][]string{"Content-Type": {"text/plain"}},
		Body:    []byte("SELECT PLACEHOLDER FROM users"),
	}

	positions := []Position{
		{ID: "pos-0", Location: "body_regex", Mode: "replace", PayloadSet: "sqli", Match: "PLACEHOLDER"},
	}

	fc := FuzzCase{
		Index:    0,
		Payloads: map[string]string{"pos-0": "DROP TABLE users;-- "},
	}

	result := engine.executeFuzzCase(
		context.Background(), baseData, positions, fc,
		"HTTP/1.x", 5*time.Second, "fuzz-1", nil, nil, checker,
	)

	if result.Error == "" {
		t.Fatal("expected safety filter error, got none")
	}
	// Verify the checker saw the expanded payload.
	if !strings.Contains(checkedBody, "DROP TABLE users;-- ") {
		t.Errorf("checker saw body %q, want containing expanded payload", checkedBody)
	}
}
