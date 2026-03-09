// Package fingerprint provides technology stack detection from HTTP responses.
//
// It uses rule-based pattern matching on response headers and body content
// to identify web servers, frameworks, programming languages, CMS platforms,
// CDN/WAF services, and JavaScript frameworks.
//
// No external dependencies are used — detection relies solely on the standard
// library and compiled regular expressions.
package fingerprint
