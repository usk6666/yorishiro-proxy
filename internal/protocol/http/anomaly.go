package http

import (
	"log/slog"
	"strings"

	"github.com/usk6666/yorishiro-proxy/internal/codec/http1/parser"
)

// anomalyTags converts parser anomalies into session tags for flow recording.
// Returns nil if no anomalies were detected, avoiding unnecessary allocations
// for normal requests.
func anomalyTags(anomalies []parser.Anomaly) map[string]string {
	if len(anomalies) == 0 {
		return nil
	}

	tags := make(map[string]string)
	var warnings []string

	for _, a := range anomalies {
		switch a.Type {
		case parser.AnomalyCLTE:
			tags["smuggling:cl_te_conflict"] = "true"
		case parser.AnomalyDuplicateCL:
			tags["smuggling:duplicate_cl"] = "true"
		case parser.AnomalyAmbiguousTE:
			tags["smuggling:ambiguous_te"] = "true"
		case parser.AnomalyInvalidTE:
			tags["smuggling:invalid_te"] = "true"
		case parser.AnomalyHeaderInjection:
			tags["smuggling:header_injection"] = "true"
		case parser.AnomalyObsFold:
			tags["smuggling:obs_fold"] = "true"
		}
		warnings = append(warnings, a.Detail)
	}

	if len(warnings) > 0 {
		tags["smuggling:warnings"] = strings.Join(warnings, "; ")
	}
	return tags
}

// logAnomalyWarnings logs detected anomaly patterns as debug messages.
// Parser anomalies replace the previous smuggling detection in smuggling.go.
func logAnomalyWarnings(logger *slog.Logger, anomalies []parser.Anomaly, method, urlStr string) {
	for _, a := range anomalies {
		logger.Debug("HTTP request anomaly detected",
			"type", string(a.Type),
			"detail", a.Detail,
			"method", method,
			"url", urlStr,
		)
	}
}
