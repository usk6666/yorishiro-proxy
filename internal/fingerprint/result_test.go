package fingerprint

import (
	"sort"
	"testing"
)

func TestResult_Names(t *testing.T) {
	r := &Result{
		Detections: []Detection{
			{Name: "nginx", Category: CategoryWebServer},
			{Name: "PHP", Category: CategoryLanguage},
		},
	}
	names := r.Names()
	sort.Strings(names)
	if len(names) != 2 || names[0] != "PHP" || names[1] != "nginx" {
		t.Errorf("Names() = %v, want [PHP nginx]", names)
	}
}

func TestResult_Names_Empty(t *testing.T) {
	r := &Result{Detections: []Detection{}}
	names := r.Names()
	if len(names) != 0 {
		t.Errorf("Names() = %v, want empty", names)
	}
}

func TestResult_ByCategory(t *testing.T) {
	r := &Result{
		Detections: []Detection{
			{Name: "nginx", Category: CategoryWebServer},
			{Name: "PHP", Category: CategoryLanguage},
			{Name: "Apache", Category: CategoryWebServer},
		},
	}
	servers := r.ByCategory(CategoryWebServer)
	if len(servers) != 2 {
		t.Errorf("ByCategory(WebServer) returned %d, want 2", len(servers))
	}
	langs := r.ByCategory(CategoryLanguage)
	if len(langs) != 1 {
		t.Errorf("ByCategory(Language) returned %d, want 1", len(langs))
	}
	cdns := r.ByCategory(CategoryCDN)
	if len(cdns) != 0 {
		t.Errorf("ByCategory(CDN) returned %d, want 0", len(cdns))
	}
}

func TestResult_Has(t *testing.T) {
	r := &Result{
		Detections: []Detection{
			{Name: "nginx", Category: CategoryWebServer},
		},
	}
	if !r.Has("nginx") {
		t.Error("Has(nginx) = false, want true")
	}
	if r.Has("Apache") {
		t.Error("Has(Apache) = true, want false")
	}
}

func TestResult_Has_Empty(t *testing.T) {
	r := &Result{Detections: []Detection{}}
	if r.Has("nginx") {
		t.Error("Has(nginx) on empty result = true, want false")
	}
}
