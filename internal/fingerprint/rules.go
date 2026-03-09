package fingerprint

import "regexp"

// matchTarget specifies where a rule should look for matches.
type matchTarget int

const (
	// targetHeader matches against a specific HTTP response header value.
	targetHeader matchTarget = iota
	// targetCookieName matches against Set-Cookie cookie names.
	targetCookieName
	// targetBody matches against the response body.
	targetBody
)

// rule defines a single detection rule.
type rule struct {
	// name is the technology name to report on match.
	name string
	// category is the technology category.
	category Category
	// target specifies what to match against.
	target matchTarget
	// header is the HTTP header name to inspect (for targetHeader).
	header string
	// pattern is the compiled regexp to match.
	// Submatch group 1, if present, captures the version string.
	pattern *regexp.Regexp
	// confidence is the detection confidence level.
	confidence string
}

// mustCompile is a helper that panics on invalid regexp (caught at init time).
func mustCompile(expr string) *regexp.Regexp {
	return regexp.MustCompile(expr)
}

// defaultRules is the built-in set of detection rules.
// Rules are evaluated in order; multiple rules can match the same response.
var defaultRules = []rule{
	// === Web Servers (Server header) ===
	{
		name: "nginx", category: CategoryWebServer, target: targetHeader,
		header: "Server", pattern: mustCompile(`(?i)nginx(?:/(\d[\d.]*))?`),
		confidence: "high",
	},
	{
		name: "Apache", category: CategoryWebServer, target: targetHeader,
		header: "Server", pattern: mustCompile(`(?i)Apache(?:/(\d[\d.]*))?`),
		confidence: "high",
	},
	{
		name: "IIS", category: CategoryWebServer, target: targetHeader,
		header: "Server", pattern: mustCompile(`(?i)Microsoft-IIS(?:/(\d[\d.]*))?`),
		confidence: "high",
	},
	{
		name: "LiteSpeed", category: CategoryWebServer, target: targetHeader,
		header: "Server", pattern: mustCompile(`(?i)LiteSpeed`),
		confidence: "high",
	},
	{
		name: "Caddy", category: CategoryWebServer, target: targetHeader,
		header: "Server", pattern: mustCompile(`(?i)Caddy`),
		confidence: "high",
	},
	{
		name: "Kestrel", category: CategoryWebServer, target: targetHeader,
		header: "Server", pattern: mustCompile(`(?i)Kestrel`),
		confidence: "high",
	},

	// === Frameworks / Languages (X-Powered-By header) ===
	{
		name: "PHP", category: CategoryLanguage, target: targetHeader,
		header: "X-Powered-By", pattern: mustCompile(`(?i)PHP(?:/(\d[\d.]*))?`),
		confidence: "high",
	},
	{
		name: "Express", category: CategoryFramework, target: targetHeader,
		header: "X-Powered-By", pattern: mustCompile(`(?i)Express`),
		confidence: "high",
	},
	{
		name: "ASP.NET", category: CategoryFramework, target: targetHeader,
		header: "X-Powered-By", pattern: mustCompile(`(?i)ASP\.NET`),
		confidence: "high",
	},
	{
		name: "Django", category: CategoryFramework, target: targetHeader,
		header: "X-Powered-By", pattern: mustCompile(`(?i)Django`),
		confidence: "high",
	},
	{
		name: "Flask", category: CategoryFramework, target: targetHeader,
		header: "X-Powered-By", pattern: mustCompile(`(?i)Flask`),
		confidence: "high",
	},

	// === Frameworks (specific headers) ===
	{
		name: "ASP.NET", category: CategoryFramework, target: targetHeader,
		header: "X-AspNet-Version", pattern: mustCompile(`(\d[\d.]*)`),
		confidence: "high",
	},
	{
		name: "ASP.NET MVC", category: CategoryFramework, target: targetHeader,
		header: "X-AspNetMvc-Version", pattern: mustCompile(`(\d[\d.]*)`),
		confidence: "high",
	},
	{
		name: "Next.js", category: CategoryFramework, target: targetHeader,
		header: "X-Powered-By", pattern: mustCompile(`(?i)Next\.js`),
		confidence: "high",
	},

	// === Languages (Set-Cookie name patterns) ===
	{
		name: "Java", category: CategoryLanguage, target: targetCookieName,
		pattern:    mustCompile(`(?i)^JSESSIONID$`),
		confidence: "medium",
	},
	{
		name: "PHP", category: CategoryLanguage, target: targetCookieName,
		pattern:    mustCompile(`(?i)^PHPSESSID$`),
		confidence: "medium",
	},
	{
		name: "ASP.NET", category: CategoryFramework, target: targetCookieName,
		pattern:    mustCompile(`(?i)^ASP\.NET_SessionId$`),
		confidence: "medium",
	},
	{
		name: "Rails", category: CategoryFramework, target: targetCookieName,
		pattern:    mustCompile(`^_[a-zA-Z0-9_]+_session$`),
		confidence: "medium",
	},
	{
		name: "Laravel", category: CategoryFramework, target: targetCookieName,
		pattern:    mustCompile(`(?i)^laravel_session$`),
		confidence: "medium",
	},
	{
		name: "Django", category: CategoryFramework, target: targetCookieName,
		pattern:    mustCompile(`(?i)^csrftoken$`),
		confidence: "low",
	},
	{
		name: "Django", category: CategoryFramework, target: targetCookieName,
		pattern:    mustCompile(`(?i)^sessionid$`),
		confidence: "low",
	},

	// === CDN / WAF (specific headers) ===
	{
		name: "Cloudflare", category: CategoryCDN, target: targetHeader,
		header: "Cf-Ray", pattern: mustCompile(`.+`),
		confidence: "high",
	},
	{
		name: "Cloudflare", category: CategoryWAF, target: targetHeader,
		header: "Server", pattern: mustCompile(`(?i)cloudflare`),
		confidence: "high",
	},
	{
		name: "CloudFront", category: CategoryCDN, target: targetHeader,
		header: "X-Amz-Cf-Id", pattern: mustCompile(`.+`),
		confidence: "high",
	},
	{
		name: "CloudFront", category: CategoryCDN, target: targetHeader,
		header: "X-Amz-Cf-Pop", pattern: mustCompile(`.+`),
		confidence: "high",
	},
	{
		name: "Akamai", category: CategoryCDN, target: targetHeader,
		header: "X-Akamai-Transformed", pattern: mustCompile(`.+`),
		confidence: "high",
	},
	{
		name: "Fastly", category: CategoryCDN, target: targetHeader,
		header: "X-Served-By", pattern: mustCompile(`(?i)cache-`),
		confidence: "medium",
	},
	{
		name: "Fastly", category: CategoryCDN, target: targetHeader,
		header: "Via", pattern: mustCompile(`(?i)varnish`),
		confidence: "medium",
	},

	// === CMS (body patterns) ===
	{
		name: "WordPress", category: CategoryCMS, target: targetBody,
		pattern:    mustCompile(`(?i)/wp-content/|/wp-includes/`),
		confidence: "high",
	},
	{
		name: "WordPress", category: CategoryCMS, target: targetHeader,
		header: "X-Powered-By", pattern: mustCompile(`(?i)WordPress`),
		confidence: "high",
	},
	{
		name: "Drupal", category: CategoryCMS, target: targetHeader,
		header: "X-Generator", pattern: mustCompile(`(?i)Drupal(?:\s+(\d[\d.]*))?`),
		confidence: "high",
	},
	{
		name: "Drupal", category: CategoryCMS, target: targetBody,
		pattern:    mustCompile(`(?i)Drupal\.settings|/sites/default/files/`),
		confidence: "medium",
	},
	{
		name: "Joomla", category: CategoryCMS, target: targetBody,
		pattern:    mustCompile(`(?i)/media/jui/|/components/com_`),
		confidence: "medium",
	},
	{
		name: "Joomla", category: CategoryCMS, target: targetHeader,
		header: "X-Content-Encoded-By", pattern: mustCompile(`(?i)Joomla`),
		confidence: "high",
	},

	// === JS Frameworks (body patterns) ===
	{
		name: "React", category: CategoryJSFramework, target: targetBody,
		pattern:    mustCompile(`data-reactroot|_reactRootContainer|__NEXT_DATA__`),
		confidence: "medium",
	},
	{
		name: "Angular", category: CategoryJSFramework, target: targetBody,
		pattern:    mustCompile(`ng-version="|ng-app="|<app-root[ >]`),
		confidence: "medium",
	},
	{
		name: "Vue.js", category: CategoryJSFramework, target: targetBody,
		pattern:    mustCompile(`data-v-[0-9a-f]+|id="__nuxt"|__VUE__`),
		confidence: "medium",
	},
	{
		name: "jQuery", category: CategoryJSFramework, target: targetBody,
		pattern:    mustCompile(`(?i)jquery[.-](\d+\.\d+(?:\.\d+)?)(?:\.min)?\.js`),
		confidence: "medium",
	},
	{
		name: "Svelte", category: CategoryJSFramework, target: targetBody,
		pattern:    mustCompile(`__svelte|svelte-[0-9a-z]+`),
		confidence: "medium",
	},

	// === Additional server/language signals ===
	{
		name: "Ruby", category: CategoryLanguage, target: targetHeader,
		header: "X-Powered-By", pattern: mustCompile(`(?i)Phusion Passenger`),
		confidence: "medium",
	},
	{
		name: "Python", category: CategoryLanguage, target: targetHeader,
		header: "Server", pattern: mustCompile(`(?i)gunicorn|uvicorn|WSGIServer`),
		confidence: "medium",
	},
	{
		name: "Go", category: CategoryLanguage, target: targetHeader,
		header: "Server", pattern: mustCompile(`(?i)^Go\b`),
		confidence: "medium",
	},
}
