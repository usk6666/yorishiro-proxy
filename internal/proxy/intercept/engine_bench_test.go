package intercept

import (
	"fmt"
	"net/http"
	"net/url"
	"testing"
)

func BenchmarkMatchesRequest(b *testing.B) {
	ruleCounts := []int{0, 1, 10, 100}

	for _, n := range ruleCounts {
		b.Run(fmt.Sprintf("rules_%d", n), func(b *testing.B) {
			engine := NewEngine()

			for i := 0; i < n; i++ {
				rule := Rule{
					ID:        fmt.Sprintf("rule-%d", i),
					Enabled:   true,
					Direction: DirectionRequest,
					Conditions: Conditions{
						HostPattern: fmt.Sprintf("host-%d\\.example\\.com", i),
						PathPattern: fmt.Sprintf("/api/v%d/.*", i),
						Methods:     []string{"GET", "POST"},
					},
				}
				if err := engine.AddRule(rule); err != nil {
					b.Fatalf("AddRule: %v", err)
				}
			}

			u, _ := url.Parse("https://nomatch.example.com/api/v999/resource")
			headers := http.Header{"Accept": {"application/json"}}

			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				engine.MatchesRequest("GET", u, h2r(headers))
			}
		})
	}
}

func BenchmarkMatchesRequest_Hit(b *testing.B) {
	ruleCounts := []int{1, 10, 100}

	for _, n := range ruleCounts {
		b.Run(fmt.Sprintf("rules_%d", n), func(b *testing.B) {
			engine := NewEngine()

			for i := 0; i < n; i++ {
				rule := Rule{
					ID:        fmt.Sprintf("rule-%d", i),
					Enabled:   true,
					Direction: DirectionRequest,
					Conditions: Conditions{
						HostPattern: fmt.Sprintf("host-%d\\.example\\.com", i),
						PathPattern: "/api/.*",
					},
				}
				if err := engine.AddRule(rule); err != nil {
					b.Fatalf("AddRule: %v", err)
				}
			}

			// Match the last rule to exercise worst-case traversal.
			target := fmt.Sprintf("https://host-%d.example.com/api/resource", n-1)
			u, _ := url.Parse(target)
			headers := http.Header{}

			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				engine.MatchesRequest("GET", u, h2r(headers))
			}
		})
	}
}

func BenchmarkMatchesRequest_WithHeaderMatch(b *testing.B) {
	engine := NewEngine()

	rule := Rule{
		ID:        "header-rule",
		Enabled:   true,
		Direction: DirectionRequest,
		Conditions: Conditions{
			HostPattern: ".*\\.example\\.com",
			PathPattern: "/api/.*",
			Methods:     []string{"POST"},
			HeaderMatch: map[string]string{
				"Content-Type":  "application/json",
				"Authorization": "Bearer .*",
			},
		},
	}
	if err := engine.AddRule(rule); err != nil {
		b.Fatalf("AddRule: %v", err)
	}

	u, _ := url.Parse("https://api.example.com/api/v1/users")
	headers := http.Header{
		"Content-Type":  {"application/json"},
		"Authorization": {"Bearer eyJhbGciOiJIUzI1NiJ9.test"},
		"Accept":        {"application/json"},
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		engine.MatchesRequest("POST", u, h2r(headers))
	}
}

func BenchmarkMatchesRequest_DisabledRules(b *testing.B) {
	engine := NewEngine()

	// Add 100 disabled rules + 1 enabled rule.
	for i := 0; i < 100; i++ {
		rule := Rule{
			ID:        fmt.Sprintf("disabled-%d", i),
			Enabled:   false,
			Direction: DirectionRequest,
			Conditions: Conditions{
				HostPattern: ".*",
			},
		}
		if err := engine.AddRule(rule); err != nil {
			b.Fatalf("AddRule: %v", err)
		}
	}
	enabledRule := Rule{
		ID:        "enabled",
		Enabled:   true,
		Direction: DirectionRequest,
		Conditions: Conditions{
			HostPattern: "target\\.example\\.com",
		},
	}
	if err := engine.AddRule(enabledRule); err != nil {
		b.Fatalf("AddRule: %v", err)
	}

	u, _ := url.Parse("https://target.example.com/path")
	headers := http.Header{}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		engine.MatchesRequest("GET", u, h2r(headers))
	}
}

func BenchmarkMatchRequestRules(b *testing.B) {
	engine := NewEngine()

	for i := 0; i < 10; i++ {
		rule := Rule{
			ID:        fmt.Sprintf("rule-%d", i),
			Enabled:   true,
			Direction: DirectionRequest,
			Conditions: Conditions{
				HostPattern: ".*\\.example\\.com",
				PathPattern: "/api/.*",
			},
		}
		if err := engine.AddRule(rule); err != nil {
			b.Fatalf("AddRule: %v", err)
		}
	}

	u, _ := url.Parse("https://api.example.com/api/v1/users")
	headers := http.Header{}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		engine.MatchRequestRules("GET", u, h2r(headers))
	}
}
