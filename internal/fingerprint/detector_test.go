package fingerprint

import (
	"testing"

	"github.com/usk6666/yorishiro-proxy/internal/protocol/http/parser"
)

func TestNewDetector(t *testing.T) {
	d := NewDetector()
	if d == nil {
		t.Fatal("NewDetector() returned nil")
	}
	if len(d.rules) == 0 {
		t.Fatal("NewDetector() has no rules")
	}
}

func TestAnalyze_EmptyInputs(t *testing.T) {
	tests := []struct {
		name    string
		headers parser.RawHeaders
		body    []byte
	}{
		{"nil inputs", nil, nil},
		{"empty inputs", parser.RawHeaders{}, []byte{}},
	}

	d := NewDetector()
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := d.Analyze(tt.headers, tt.body)
			if result == nil {
				t.Fatal("Analyze() returned nil")
			}
			if len(result.Detections) != 0 {
				t.Errorf("expected 0 detections, got %d", len(result.Detections))
			}
		})
	}
}

func TestAnalyze_WebServers(t *testing.T) {
	tests := []struct {
		name        string
		server      string
		wantName    string
		wantVersion string
	}{
		{"nginx with version", "nginx/1.25.3", "nginx", "1.25.3"},
		{"nginx without version", "nginx", "nginx", ""},
		{"Apache with version", "Apache/2.4.58", "Apache", "2.4.58"},
		{"Apache without version", "Apache", "Apache", ""},
		{"IIS with version", "Microsoft-IIS/10.0", "IIS", "10.0"},
		{"LiteSpeed", "LiteSpeed", "LiteSpeed", ""},
		{"Caddy", "Caddy", "Caddy", ""},
		{"Kestrel", "Kestrel", "Kestrel", ""},
	}

	d := NewDetector()
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h := parser.RawHeaders{}
			h.Set("Server", tt.server)
			result := d.Analyze(h, nil)
			if !result.Has(tt.wantName) {
				t.Errorf("expected detection of %q for Server: %q", tt.wantName, tt.server)
				return
			}
			dets := result.ByCategory(CategoryWebServer)
			for _, det := range dets {
				if det.Name == tt.wantName {
					if det.Version != tt.wantVersion {
						t.Errorf("version = %q, want %q", det.Version, tt.wantVersion)
					}
					if det.Confidence != "high" {
						t.Errorf("confidence = %q, want high", det.Confidence)
					}
				}
			}
		})
	}
}

func TestAnalyze_XPoweredBy(t *testing.T) {
	tests := []struct {
		name        string
		value       string
		wantName    string
		wantCat     Category
		wantVersion string
	}{
		{"PHP", "PHP/8.2.3", "PHP", CategoryLanguage, "8.2.3"},
		{"Express", "Express", "Express", CategoryFramework, ""},
		{"ASP.NET", "ASP.NET", "ASP.NET", CategoryFramework, ""},
		{"Next.js", "Next.js", "Next.js", CategoryFramework, ""},
	}

	d := NewDetector()
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h := parser.RawHeaders{}
			h.Set("X-Powered-By", tt.value)
			result := d.Analyze(h, nil)
			if !result.Has(tt.wantName) {
				t.Errorf("expected detection of %q", tt.wantName)
				return
			}
			for _, det := range result.Detections {
				if det.Name == tt.wantName && det.Category == tt.wantCat {
					if det.Version != tt.wantVersion {
						t.Errorf("version = %q, want %q", det.Version, tt.wantVersion)
					}
				}
			}
		})
	}
}

func TestAnalyze_CookieDetection(t *testing.T) {
	tests := []struct {
		name     string
		cookie   string
		wantName string
		wantCat  Category
	}{
		{"Java JSESSIONID", "JSESSIONID=abc123; Path=/", "Java", CategoryLanguage},
		{"PHP PHPSESSID", "PHPSESSID=xyz789; Path=/", "PHP", CategoryLanguage},
		{"ASP.NET session", "ASP.NET_SessionId=abc; Path=/", "ASP.NET", CategoryFramework},
		{"Rails session", "_myapp_session=abc; Path=/", "Rails", CategoryFramework},
		{"Laravel session", "laravel_session=abc; Path=/", "Laravel", CategoryFramework},
	}

	d := NewDetector()
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h := parser.RawHeaders{
				{Name: "Set-Cookie", Value: tt.cookie},
			}
			result := d.Analyze(h, nil)
			if !result.Has(tt.wantName) {
				t.Errorf("expected detection of %q from cookie %q, got: %v",
					tt.wantName, tt.cookie, result.Names())
			}
		})
	}
}

func TestAnalyze_CDN_WAF(t *testing.T) {
	tests := []struct {
		name     string
		headers  map[string]string
		wantName string
		wantCat  Category
	}{
		{
			"Cloudflare via Cf-Ray",
			map[string]string{"Cf-Ray": "abc123-LAX"},
			"Cloudflare", CategoryCDN,
		},
		{
			"Cloudflare via Server",
			map[string]string{"Server": "cloudflare"},
			"Cloudflare", CategoryWAF,
		},
		{
			"CloudFront via X-Amz-Cf-Id",
			map[string]string{"X-Amz-Cf-Id": "abc123"},
			"CloudFront", CategoryCDN,
		},
		{
			"CloudFront via X-Amz-Cf-Pop",
			map[string]string{"X-Amz-Cf-Pop": "NRT51-C1"},
			"CloudFront", CategoryCDN,
		},
		{
			"Akamai",
			map[string]string{"X-Akamai-Transformed": "9 - 0 pmb=mRUM,3"},
			"Akamai", CategoryCDN,
		},
		{
			"Fastly via Via",
			map[string]string{"Via": "1.1 varnish"},
			"Fastly", CategoryCDN,
		},
	}

	d := NewDetector()
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h := parser.RawHeaders{}
			for k, v := range tt.headers {
				h.Set(k, v)
			}
			result := d.Analyze(h, nil)
			found := false
			for _, det := range result.Detections {
				if det.Name == tt.wantName && det.Category == tt.wantCat {
					found = true
					break
				}
			}
			if !found {
				t.Errorf("expected %q (%s), got: %v", tt.wantName, tt.wantCat, result.Names())
			}
		})
	}
}

func TestAnalyze_BodyPatterns(t *testing.T) {
	tests := []struct {
		name     string
		body     string
		wantName string
		wantCat  Category
	}{
		{
			"WordPress wp-content",
			`<link rel="stylesheet" href="/wp-content/themes/style.css">`,
			"WordPress", CategoryCMS,
		},
		{
			"WordPress wp-includes",
			`<script src="/wp-includes/js/jquery.js"></script>`,
			"WordPress", CategoryCMS,
		},
		{
			"Drupal settings",
			`<script>jQuery.extend(Drupal.settings, {"basePath":"/"});</script>`,
			"Drupal", CategoryCMS,
		},
		{
			"Joomla components",
			`<script src="/components/com_content/views/article.js"></script>`,
			"Joomla", CategoryCMS,
		},
		{
			"React data-reactroot",
			`<div id="app" data-reactroot="">`,
			"React", CategoryJSFramework,
		},
		{
			"React __NEXT_DATA__",
			`<script id="__NEXT_DATA__" type="application/json">{}`,
			"React", CategoryJSFramework,
		},
		{
			"Angular ng-version",
			`<app-root ng-version="17.2.1">`,
			"Angular", CategoryJSFramework,
		},
		{
			"Vue.js data attribute",
			`<div data-v-7ba5bd90 class="container">`,
			"Vue.js", CategoryJSFramework,
		},
		{
			"Vue.js __nuxt",
			`<div id="__nuxt">`,
			"Vue.js", CategoryJSFramework,
		},
		{
			"jQuery",
			`<script src="/js/jquery-3.7.1.min.js"></script>`,
			"jQuery", CategoryJSFramework,
		},
		{
			"Svelte",
			`<div class="svelte-1abc2de">`,
			"Svelte", CategoryJSFramework,
		},
	}

	d := NewDetector()
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := d.Analyze(parser.RawHeaders{}, []byte(tt.body))
			found := false
			for _, det := range result.Detections {
				if det.Name == tt.wantName && det.Category == tt.wantCat {
					found = true
					break
				}
			}
			if !found {
				t.Errorf("expected %q (%s) from body, got: %v", tt.wantName, tt.wantCat, result.Names())
			}
		})
	}
}

func TestAnalyze_MultipleDetections(t *testing.T) {
	d := NewDetector()
	h := parser.RawHeaders{
		{Name: "Server", Value: "nginx/1.25.3"},
		{Name: "X-Powered-By", Value: "PHP/8.2.3"},
		{Name: "Set-Cookie", Value: "PHPSESSID=abc123; Path=/"},
	}
	body := []byte(`<link href="/wp-content/themes/style.css">`)

	result := d.Analyze(h, body)

	expected := []string{"nginx", "PHP", "WordPress"}
	for _, name := range expected {
		if !result.Has(name) {
			t.Errorf("expected detection of %q in multi-signal response, got: %v",
				name, result.Names())
		}
	}
}

func TestAnalyze_Deduplication(t *testing.T) {
	d := NewDetector()
	h := parser.RawHeaders{
		{Name: "X-Powered-By", Value: "PHP/8.2.3"},
		{Name: "Set-Cookie", Value: "PHPSESSID=abc123; Path=/"},
	}

	result := d.Analyze(h, nil)

	// PHP should appear once (from X-Powered-By, high confidence with version)
	// not duplicated from cookie detection.
	count := 0
	for _, det := range result.Detections {
		if det.Name == "PHP" && det.Category == CategoryLanguage {
			count++
			if det.Version != "8.2.3" {
				t.Errorf("PHP version = %q, want 8.2.3", det.Version)
			}
			if det.Confidence != "high" {
				t.Errorf("PHP confidence = %q, want high", det.Confidence)
			}
		}
	}
	if count != 1 {
		t.Errorf("expected exactly 1 PHP language detection, got %d", count)
	}
}

func TestAnalyze_ASPNETHeaders(t *testing.T) {
	d := NewDetector()
	h := parser.RawHeaders{}
	h.Set("X-AspNet-Version", "4.0.30319")
	h.Set("X-AspNetMvc-Version", "5.2.7")

	result := d.Analyze(h, nil)

	if !result.Has("ASP.NET") {
		t.Error("expected ASP.NET detection from X-AspNet-Version")
	}
	if !result.Has("ASP.NET MVC") {
		t.Error("expected ASP.NET MVC detection from X-AspNetMvc-Version")
	}

	for _, det := range result.Detections {
		if det.Name == "ASP.NET" && det.Version == "4.0.30319" {
			return // found the right version
		}
	}
	t.Error("expected ASP.NET with version 4.0.30319")
}

func TestAnalyze_LanguageServers(t *testing.T) {
	tests := []struct {
		name     string
		server   string
		wantName string
	}{
		{"Python gunicorn", "gunicorn/21.2.0", "Python"},
		{"Python uvicorn", "uvicorn", "Python"},
		{"Go server", "Go", "Go"},
	}

	d := NewDetector()
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h := parser.RawHeaders{}
			h.Set("Server", tt.server)
			result := d.Analyze(h, nil)
			if !result.Has(tt.wantName) {
				t.Errorf("expected %q from Server: %q, got: %v",
					tt.wantName, tt.server, result.Names())
			}
		})
	}
}

func TestAnalyze_DrupalGenerator(t *testing.T) {
	d := NewDetector()
	h := parser.RawHeaders{}
	h.Set("X-Generator", "Drupal 10")

	result := d.Analyze(h, nil)
	if !result.Has("Drupal") {
		t.Error("expected Drupal detection from X-Generator")
	}
	for _, det := range result.Detections {
		if det.Name == "Drupal" {
			if det.Version != "10" {
				t.Errorf("Drupal version = %q, want 10", det.Version)
			}
		}
	}
}

func TestAnalyze_JoomlaHeader(t *testing.T) {
	d := NewDetector()
	h := parser.RawHeaders{}
	h.Set("X-Content-Encoded-By", "Joomla! 4.3")

	result := d.Analyze(h, nil)
	if !result.Has("Joomla") {
		t.Errorf("expected Joomla from X-Content-Encoded-By, got: %v", result.Names())
	}
}

func TestAnalyze_NoFalsePositives(t *testing.T) {
	d := NewDetector()
	h := parser.RawHeaders{}
	h.Set("Content-Type", "text/html; charset=utf-8")
	h.Set("Content-Length", "1234")
	body := []byte(`<html><body><h1>Hello World</h1></body></html>`)

	result := d.Analyze(h, body)
	if len(result.Detections) != 0 {
		t.Errorf("expected no detections for generic response, got: %v", result.Names())
	}
}

func TestAnalyze_CaseInsensitive(t *testing.T) {
	d := NewDetector()
	h := parser.RawHeaders{}
	h.Set("Server", "NGINX/1.20.0")

	result := d.Analyze(h, nil)
	if !result.Has("nginx") {
		t.Error("expected case-insensitive nginx detection")
	}
}

func TestAnalyze_RubyPassenger(t *testing.T) {
	d := NewDetector()
	h := parser.RawHeaders{}
	h.Set("X-Powered-By", "Phusion Passenger 6.0.18")

	result := d.Analyze(h, nil)
	if !result.Has("Ruby") {
		t.Errorf("expected Ruby from Phusion Passenger, got: %v", result.Names())
	}
}

func TestAddDetection_NoConfidenceDowngrade(t *testing.T) {
	// F-1: A lower-confidence detection with a version should NOT replace
	// a higher-confidence detection. It should only copy the version string.
	seen := make(map[string]Detection)

	// First: high-confidence detection without version (e.g., from Server header).
	highRule := rule{
		name: "nginx", category: CategoryWebServer,
		confidence: "high",
	}
	addDetection(seen, highRule, "")

	// Second: medium-confidence detection with version (e.g., from body pattern).
	medRule := rule{
		name: "nginx", category: CategoryWebServer,
		confidence: "medium",
	}
	addDetection(seen, medRule, "1.20")

	det := seen["nginx|"+string(CategoryWebServer)]
	if det.Confidence != "high" {
		t.Errorf("confidence = %q, want high (should not be downgraded)", det.Confidence)
	}
	if det.Version != "1.20" {
		t.Errorf("version = %q, want 1.20 (should be merged from lower-confidence)", det.Version)
	}
}

func TestAnalyze_jQueryVersionExtraction(t *testing.T) {
	tests := []struct {
		name        string
		body        string
		wantVersion string
	}{
		{
			"minified jQuery",
			`<script src="/js/jquery-3.7.1.min.js"></script>`,
			"3.7.1",
		},
		{
			"non-minified jQuery",
			`<script src="/js/jquery-3.6.0.js"></script>`,
			"3.6.0",
		},
	}

	d := NewDetector()
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := d.Analyze(parser.RawHeaders{}, []byte(tt.body))
			if !result.Has("jQuery") {
				t.Fatalf("expected jQuery detection, got: %v", result.Names())
			}
			for _, det := range result.Detections {
				if det.Name == "jQuery" {
					if det.Version != tt.wantVersion {
						t.Errorf("version = %q, want %q", det.Version, tt.wantVersion)
					}
				}
			}
		})
	}
}
