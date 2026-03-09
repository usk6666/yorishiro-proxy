package fingerprint

// Category represents the type of technology detected.
type Category string

const (
	// CategoryWebServer identifies HTTP server software (e.g., nginx, Apache).
	CategoryWebServer Category = "web_server"
	// CategoryFramework identifies web application frameworks (e.g., Rails, Django).
	CategoryFramework Category = "framework"
	// CategoryLanguage identifies server-side programming languages (e.g., PHP, Java).
	CategoryLanguage Category = "language"
	// CategoryCMS identifies content management systems (e.g., WordPress, Drupal).
	CategoryCMS Category = "cms"
	// CategoryCDN identifies content delivery networks (e.g., Cloudflare, CloudFront).
	CategoryCDN Category = "cdn"
	// CategoryWAF identifies web application firewalls (e.g., ModSecurity, Cloudflare WAF).
	CategoryWAF Category = "waf"
	// CategoryJSFramework identifies client-side JavaScript frameworks (e.g., React, Angular).
	CategoryJSFramework Category = "js_framework"
)

// Detection represents a single technology detection result.
type Detection struct {
	// Name is the technology name (e.g., "nginx", "React").
	Name string `json:"name"`
	// Version is the detected version string, if available.
	// Empty string means version could not be determined.
	Version string `json:"version,omitempty"`
	// Category is the technology category.
	Category Category `json:"category"`
	// Confidence indicates how reliable the detection is.
	// "high" means a strong signal (e.g., explicit header value).
	// "medium" means a reasonable indicator (e.g., cookie name pattern).
	// "low" means a weak hint (e.g., body content pattern).
	Confidence string `json:"confidence"`
}

// Result holds all technology detections for a single HTTP response.
type Result struct {
	// Detections is the list of detected technologies.
	Detections []Detection `json:"detections"`
}

// Names returns the technology names from all detections.
func (r *Result) Names() []string {
	names := make([]string, len(r.Detections))
	for i, d := range r.Detections {
		names[i] = d.Name
	}
	return names
}

// ByCategory returns detections filtered by the given category.
func (r *Result) ByCategory(cat Category) []Detection {
	var out []Detection
	for _, d := range r.Detections {
		if d.Category == cat {
			out = append(out, d)
		}
	}
	return out
}

// Has returns true if a technology with the given name was detected.
func (r *Result) Has(name string) bool {
	for _, d := range r.Detections {
		if d.Name == name {
			return true
		}
	}
	return false
}
