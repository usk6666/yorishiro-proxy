package macro

import (
	"fmt"
	"regexp"
	"strings"
)

// EvaluateGuard evaluates a step guard condition against the results of previous steps.
// Returns true if the step should be executed, false if it should be skipped.
// If the guard is nil, the step always executes.
func EvaluateGuard(guard *Guard, stepResults map[string]*stepState, kvStore map[string]string) (bool, error) {
	if guard == nil {
		return true, nil
	}

	result, err := evaluateConditions(guard, stepResults, kvStore)
	if err != nil {
		return false, err
	}

	if guard.Negate {
		return !result, nil
	}
	return result, nil
}

// stepState holds the execution state of a completed step for guard evaluation.
type stepState struct {
	// StatusCode is the HTTP response status code.
	StatusCode int
	// Headers are the response headers.
	Headers map[string][]string
	// Body is the response body.
	Body []byte
	// Skipped indicates the step was skipped (guard condition not met).
	Skipped bool
}

// evaluateConditions evaluates all conditions in the guard using AND logic.
// All specified conditions must be true for the overall result to be true.
func evaluateConditions(guard *Guard, stepResults map[string]*stepState, kvStore map[string]string) (bool, error) {
	// Look up the referenced step.
	if guard.Step == "" {
		// No step reference. Only extracted_var can be evaluated.
		if guard.ExtractedVar != "" {
			_, exists := kvStore[guard.ExtractedVar]
			return exists, nil
		}
		return false, fmt.Errorf("guard must reference a step or use extracted_var")
	}

	state, exists := stepResults[guard.Step]
	if !exists {
		return false, nil
	}

	// Skipped steps are treated as not matching.
	if state.Skipped {
		return false, nil
	}

	// All conditions must pass (AND).
	conditions := 0

	checkers := []func() (bool, error){
		func() (bool, error) { return checkStatusCode(guard, state, &conditions) },
		func() (bool, error) { return checkStatusCodeRange(guard, state, &conditions) },
		func() (bool, error) { return checkHeaderMatch(guard, state, &conditions) },
		func() (bool, error) { return checkBodyMatch(guard, state, &conditions) },
		func() (bool, error) { return checkExtractedVar(guard, kvStore, &conditions) },
	}

	for _, check := range checkers {
		ok, err := check()
		if err != nil {
			return false, err
		}
		if !ok {
			return false, nil
		}
	}

	// If no conditions were specified at all (just a step reference),
	// treat it as checking that the step executed successfully.
	return true, nil
}

// checkStatusCode checks if the step's status code matches the guard's expected status code.
func checkStatusCode(guard *Guard, state *stepState, conditions *int) (bool, error) {
	if guard.StatusCode == nil {
		return true, nil
	}
	*conditions++
	return state.StatusCode == *guard.StatusCode, nil
}

// checkStatusCodeRange checks if the step's status code falls within the guard's range.
func checkStatusCodeRange(guard *Guard, state *stepState, conditions *int) (bool, error) {
	if guard.StatusCodeRange[0] == 0 && guard.StatusCodeRange[1] == 0 {
		return true, nil
	}
	*conditions++
	return state.StatusCode >= guard.StatusCodeRange[0] && state.StatusCode <= guard.StatusCodeRange[1], nil
}

// checkHeaderMatch checks if the step's headers match the guard's header patterns.
func checkHeaderMatch(guard *Guard, state *stepState, conditions *int) (bool, error) {
	if len(guard.HeaderMatch) == 0 {
		return true, nil
	}
	*conditions++
	match, err := matchHeaders(guard.HeaderMatch, state.Headers)
	if err != nil {
		return false, fmt.Errorf("header_match evaluation: %w", err)
	}
	return match, nil
}

// checkBodyMatch checks if the step's body matches the guard's body pattern.
func checkBodyMatch(guard *Guard, state *stepState, conditions *int) (bool, error) {
	if guard.BodyMatch == "" {
		return true, nil
	}
	*conditions++
	match, err := matchBody(guard.BodyMatch, state.Body)
	if err != nil {
		return false, fmt.Errorf("body_match evaluation: %w", err)
	}
	return match, nil
}

// checkExtractedVar checks if the guard's referenced variable exists in the KV store.
func checkExtractedVar(guard *Guard, kvStore map[string]string, conditions *int) (bool, error) {
	if guard.ExtractedVar == "" {
		return true, nil
	}
	*conditions++
	_, exists := kvStore[guard.ExtractedVar]
	return exists, nil
}

// matchHeaders checks if all header patterns match (AND evaluation).
// Pattern length and input size are validated to mitigate ReDoS (CWE-1333).
func matchHeaders(patterns map[string]string, headers map[string][]string) (bool, error) {
	for headerName, pattern := range patterns {
		if len(pattern) > MaxRegexPatternLen {
			return false, fmt.Errorf("regex pattern too long for header %q: %d > %d", headerName, len(pattern), MaxRegexPatternLen)
		}
		values := findHeader(headers, headerName)
		if len(values) == 0 {
			return false, nil
		}
		combined := strings.Join(values, ", ")
		// Cap input size to prevent CPU exhaustion.
		if len(combined) > MaxRegexInputSize {
			combined = combined[:MaxRegexInputSize]
		}
		re, err := regexp.Compile(pattern)
		if err != nil {
			return false, fmt.Errorf("invalid regex %q for header %q: %w", pattern, headerName, err)
		}
		if !re.MatchString(combined) {
			return false, nil
		}
	}
	return true, nil
}

// matchBody checks if the body matches the given regex pattern.
// Pattern length and input size are validated to mitigate ReDoS (CWE-1333).
func matchBody(pattern string, body []byte) (bool, error) {
	if len(body) == 0 {
		return false, nil
	}
	if len(pattern) > MaxRegexPatternLen {
		return false, fmt.Errorf("regex pattern too long: %d > %d", len(pattern), MaxRegexPatternLen)
	}
	re, err := regexp.Compile(pattern)
	if err != nil {
		return false, fmt.Errorf("invalid regex %q: %w", pattern, err)
	}
	// Cap input size to prevent CPU exhaustion on large bodies.
	if len(body) > MaxRegexInputSize {
		body = body[:MaxRegexInputSize]
	}
	return re.Match(body), nil
}
