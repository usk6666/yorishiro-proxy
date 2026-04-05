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
	opts := flow.StreamListOptions{
		State: "complete",
		Limit: maxListLimit,
	}
	flowList, err := s.deps.store.ListStreams(ctx, opts)
	if err != nil {
		return nil, nil, fmt.Errorf("list flows: %w", err)
	}

	hostMap := s.aggregateTechnologies(ctx, flowList)
	hosts := buildSortedHosts(hostMap)

	return nil, &queryTechnologiesResult{
		Hosts: hosts,
		Count: len(hosts),
	}, nil
}

// aggregateTechnologies collects unique technologies per host from the given flows.
// Key: host, Value: map of "name|category" -> technologyEntry (dedup by name+category, keep best version).
func (s *Server) aggregateTechnologies(ctx context.Context, flowList []*flow.Stream) map[string]map[string]technologyEntry {
	hostMap := make(map[string]map[string]technologyEntry)

	for _, fl := range flowList {
		detections, host := s.extractFlowTechnologies(ctx, fl)
		if host == "" || len(detections) == 0 {
			continue
		}

		if hostMap[host] == nil {
			hostMap[host] = make(map[string]technologyEntry)
		}
		mergeDetections(hostMap[host], detections)
	}
	return hostMap
}

// extractFlowTechnologies parses technology detections from a flow's tags
// and resolves the associated host. Returns nil detections or empty host on failure.
func (s *Server) extractFlowTechnologies(ctx context.Context, fl *flow.Stream) ([]fingerprint.Detection, string) {
	techJSON, ok := fl.Tags["technologies"]
	if !ok || techJSON == "" {
		return nil, ""
	}

	var detections []fingerprint.Detection
	if err := json.Unmarshal([]byte(techJSON), &detections); err != nil {
		return nil, ""
	}
	if len(detections) == 0 {
		return nil, ""
	}

	host := extractHostFromFlow(ctx, s, fl)
	return detections, host
}

// mergeDetections merges fingerprint detections into an existing technology map,
// deduplicating by name+category and preferring entries that have a version.
func mergeDetections(techMap map[string]technologyEntry, detections []fingerprint.Detection) {
	for _, d := range detections {
		key := d.Name + "|" + string(d.Category)
		existing, exists := techMap[key]
		if !exists || (existing.Version == "" && d.Version != "") {
			techMap[key] = technologyEntry{
				Name:       d.Name,
				Version:    d.Version,
				Category:   string(d.Category),
				Confidence: d.Confidence,
			}
		}
	}
}

// buildSortedHosts converts a host-to-technologies map into a sorted slice of hostTechnologies.
func buildSortedHosts(hostMap map[string]map[string]technologyEntry) []hostTechnologies {
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
	return hosts
}

// extractHostFromFlow retrieves the host from the first send message of a flow.
func extractHostFromFlow(ctx context.Context, s *Server, fl *flow.Stream) string {
	msgs, err := s.deps.store.GetFlows(ctx, fl.ID, flow.FlowListOptions{Direction: "send"})
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
