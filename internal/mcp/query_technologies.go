package mcp

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"

	gomcp "github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/usk6666/yorishiro-proxy/internal/fingerprint"
	"github.com/usk6666/yorishiro-proxy/internal/flow"
)

// --- technologies resource ---

// technologyEntry is a single technology detection entry in the technologies response.
type technologyEntry struct {
	Name       string `json:"name"`
	Version    string `json:"version,omitempty"`
	Category   string `json:"category"`
	Confidence string `json:"confidence"`
}

// hostTechnologies groups detected technologies by host.
type hostTechnologies struct {
	Host         string            `json:"host"`
	Technologies []technologyEntry `json:"technologies"`
}

// queryTechnologiesResult is the response for the technologies resource.
type queryTechnologiesResult struct {
	Hosts []hostTechnologies `json:"hosts"`
	Count int                `json:"count"`
}

// handleQueryTechnologies aggregates detected technologies per host across all flows.
func (s *Server) handleQueryTechnologies(ctx context.Context, input queryInput) (*gomcp.CallToolResult, *queryTechnologiesResult, error) {
	if s.deps.store == nil {
		return nil, nil, fmt.Errorf("flow store is not initialized")
	}

	// Fetch all complete flows (no pagination needed for aggregation).
	opts := flow.ListOptions{
		State: "complete",
		Limit: maxListLimit,
	}
	flowList, err := s.deps.store.ListFlows(ctx, opts)
	if err != nil {
		return nil, nil, fmt.Errorf("list flows: %w", err)
	}

	// hostMap aggregates unique technologies per host.
	// Key: host, Value: map of "name|category" -> technologyEntry (dedup by name+category, keep best version).
	hostMap := make(map[string]map[string]technologyEntry)

	for _, fl := range flowList {
		techJSON, ok := fl.Tags["technologies"]
		if !ok || techJSON == "" {
			continue
		}

		var detections []fingerprint.Detection
		if err := json.Unmarshal([]byte(techJSON), &detections); err != nil {
			continue
		}
		if len(detections) == 0 {
			continue
		}

		// Extract the host from the first send message.
		host := extractHostFromFlow(ctx, s, fl)
		if host == "" {
			continue
		}

		if hostMap[host] == nil {
			hostMap[host] = make(map[string]technologyEntry)
		}
		for _, d := range detections {
			key := d.Name + "|" + string(d.Category)
			existing, exists := hostMap[host][key]
			if !exists || (existing.Version == "" && d.Version != "") {
				hostMap[host][key] = technologyEntry{
					Name:       d.Name,
					Version:    d.Version,
					Category:   string(d.Category),
					Confidence: d.Confidence,
				}
			}
		}
	}

	// Convert hostMap to sorted output.
	hosts := make([]hostTechnologies, 0, len(hostMap))
	for host, techMap := range hostMap {
		techs := make([]technologyEntry, 0, len(techMap))
		for _, t := range techMap {
			techs = append(techs, t)
		}
		sort.Slice(techs, func(i, j int) bool {
			if techs[i].Category != techs[j].Category {
				return techs[i].Category < techs[j].Category
			}
			return techs[i].Name < techs[j].Name
		})
		hosts = append(hosts, hostTechnologies{
			Host:         host,
			Technologies: techs,
		})
	}
	sort.Slice(hosts, func(i, j int) bool {
		return hosts[i].Host < hosts[j].Host
	})

	return nil, &queryTechnologiesResult{
		Hosts: hosts,
		Count: len(hosts),
	}, nil
}

// extractHostFromFlow retrieves the host from the first send message of a flow.
func extractHostFromFlow(ctx context.Context, s *Server, fl *flow.Flow) string {
	msgs, err := s.deps.store.GetMessages(ctx, fl.ID, flow.MessageListOptions{Direction: "send"})
	if err != nil || len(msgs) == 0 {
		return ""
	}
	// Use the last send message (modified variant if present).
	msg := msgs[len(msgs)-1]
	if msg.URL != nil {
		return msg.URL.Hostname()
	}
	// Fallback to Host header.
	if hosts := msg.Headers["Host"]; len(hosts) > 0 {
		return hosts[0]
	}
	return ""
}
