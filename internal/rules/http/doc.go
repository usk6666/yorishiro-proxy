// Package http provides HTTP-specific rule engines for intercept, transform,
// and safety filtering. Each engine operates on envelope.HTTPMessage and
// follows RFC-001 section 3.6.
//
// InterceptEngine matches HTTP requests/responses against configurable rules
// and returns matched rule IDs for the HoldQueue.
//
// TransformEngine applies header and body modifications in priority order.
//
// SafetyEngine checks HTTP requests against input safety rules (destructive
// SQL, OS commands) and returns violations.
package http
