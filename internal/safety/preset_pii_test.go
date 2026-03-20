package safety

import (
	"regexp"
	"testing"
)

func TestCreditCardRules_Match(t *testing.T) {
	tests := []struct {
		name    string
		ruleID  string
		input   string
		matched bool
	}{
		// credit-card:separated
		{"visa separated dash", "credit-card:separated", "card: 4111-1111-1111-1111", true},
		{"visa separated space", "credit-card:separated", "card: 4111 1111 1111 1111", true},
		{"mastercard separated", "credit-card:separated", "5500-0000-0000-0004", true},
		{"amex 15 digits separated", "credit-card:separated", "3782-8224-6310-005", false},
		{"short separated", "credit-card:separated", "1234-5678", false},

		// credit-card:continuous
		{"visa continuous", "credit-card:continuous", "card: 4111111111111111", true},
		{"mastercard continuous", "credit-card:continuous", "5500000000000004", true},
		{"13 digit valid", "credit-card:continuous", "0000000000000", true}, // Luhn valid
		{"too short 12 digits", "credit-card:continuous", "411111111111", false},
		{"invalid luhn", "credit-card:continuous", "4111111111111112", false},
	}

	ruleMap := buildRuleMap(t, creditCardRules)

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			re, ok := ruleMap[tt.ruleID]
			if !ok {
				t.Fatalf("rule %q not found", tt.ruleID)
			}

			// For continuous rule, also apply validator.
			locs := re.FindAllIndex([]byte(tt.input), -1)
			got := false
			for _, loc := range locs {
				match := []byte(tt.input)[loc[0]:loc[1]]
				rc := findPresetRule(creditCardRules, tt.ruleID)
				if rc.Validator != nil {
					if rc.Validator(match) {
						got = true
					}
				} else {
					got = true
				}
			}
			if got != tt.matched {
				t.Errorf("rule %s on %q: got %v, want %v", tt.ruleID, tt.input, got, tt.matched)
			}
		})
	}
}

func TestLuhnValid(t *testing.T) {
	tests := []struct {
		name  string
		input string
		valid bool
	}{
		// Valid card numbers.
		{"Visa", "4111111111111111", true},
		{"Visa 2", "4012888888881881", true},
		{"Mastercard", "5500000000000004", true},
		{"Mastercard 2", "5105105105105100", true},
		{"Amex", "378282246310005", true},
		{"Discover", "6011111111111117", true},
		{"Diners Club", "30569309025904", true},
		{"JCB", "3530111333300000", true},

		// Invalid numbers.
		{"Visa invalid", "4111111111111112", false},
		{"Sequential", "1234567890123456", false},
		{"All ones", "1111111111111111", false},
		{"All twos", "2222222222222222", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := luhnValid([]byte(tt.input))
			if got != tt.valid {
				t.Errorf("luhnValid(%q) = %v, want %v", tt.input, got, tt.valid)
			}
		})
	}
}

func TestMyNumberValid(t *testing.T) {
	tests := []struct {
		name  string
		input string
		valid bool
	}{
		// Valid My Numbers (generated using the official check digit algorithm).
		{"valid 1", "123456789018", true},
		{"valid with spaces", "1234 5678 9018", true},

		// Invalid My Numbers.
		{"invalid check digit", "123456789012", false},
		{"all zeros is valid", "000000000000", true},
		{"too short", "12345678901", false},
		{"too long", "1234567890123", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := myNumberValid([]byte(tt.input))
			if got != tt.valid {
				t.Errorf("myNumberValid(%q) = %v, want %v", tt.input, got, tt.valid)
			}
		})
	}
}

func TestMyNumberCheckDigit(t *testing.T) {
	// Test the algorithm directly with known values.
	// My Number: 123456789018
	// Check digit computation:
	// digits: [1,2,3,4,5,6,7,8,9,0,1,8]
	tests := []struct {
		name   string
		digits []int
		valid  bool
	}{
		{"valid", []int{1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 8}, true},
		{"invalid", []int{1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 0}, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := myNumberCheckDigit(tt.digits)
			if got != tt.valid {
				t.Errorf("myNumberCheckDigit(%v) = %v, want %v", tt.digits, got, tt.valid)
			}
		})
	}
}

func TestEmailRules_Match(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		matched bool
	}{
		{"standard email", "user@example.com", true},
		{"email with dots", "first.last@example.com", true},
		{"email with plus", "user+tag@example.com", true},
		{"email with dash domain", "user@my-domain.co.jp", true},
		{"email with subdomain", "user@sub.domain.com", true},
		{"email with percent", "user%name@example.com", true},
		{"no at sign", "userexample.com", false},
		{"no domain", "user@", false},
		{"no tld", "user@example", false},
		{"single char tld", "user@example.c", false},
	}

	re := compilePIIPattern(t, emailRules[0].Pattern)

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := re.MatchString(tt.input)
			if got != tt.matched {
				t.Errorf("email pattern on %q: got %v, want %v", tt.input, got, tt.matched)
			}
		})
	}
}

func TestJapanPhoneRules_Match(t *testing.T) {
	tests := []struct {
		name    string
		ruleID  string
		input   string
		matched bool
	}{
		// japan-phone:mobile
		{"mobile 090", "japan-phone:mobile", "090-1234-5678", true},
		{"mobile 080", "japan-phone:mobile", "080-1234-5678", true},
		{"mobile 070", "japan-phone:mobile", "070-1234-5678", true},
		{"mobile no dash", "japan-phone:mobile", "09012345678", true},
		{"mobile spaces", "japan-phone:mobile", "090 1234 5678", true},
		{"not mobile prefix", "japan-phone:mobile", "060-1234-5678", false},

		// japan-phone:landline
		{"tokyo landline", "japan-phone:landline", "03-1234-5678", true},
		{"osaka landline", "japan-phone:landline", "06-1234-5678", true},
		{"regional 4 digit area", "japan-phone:landline", "0123-45-6789", true},
		{"landline no dash", "japan-phone:landline", "0312345678", true},
		{"landline spaces", "japan-phone:landline", "03 1234 5678", true},
	}

	ruleMap := buildRuleMap(t, japanPhoneRules)

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			re, ok := ruleMap[tt.ruleID]
			if !ok {
				t.Fatalf("rule %q not found", tt.ruleID)
			}
			got := re.MatchString(tt.input)
			if got != tt.matched {
				t.Errorf("rule %s on %q: got %v, want %v", tt.ruleID, tt.input, got, tt.matched)
			}
		})
	}
}

func TestPIIPresets_DefaultReplacement(t *testing.T) {
	tests := []struct {
		preset      string
		replacement string
	}{
		{PresetCreditCard, "[MASKED:credit_card]"},
		{PresetJapanMyNumber, "[MASKED:my_number]"},
		{PresetEmail, "[MASKED:email]"},
		{PresetJapanPhone, "[MASKED:phone]"},
	}

	for _, tt := range tests {
		t.Run(tt.preset, func(t *testing.T) {
			p, err := LookupPreset(tt.preset)
			if err != nil {
				t.Fatalf("lookup error: %v", err)
			}
			for _, rc := range p.Rules {
				if rc.Replacement != tt.replacement {
					t.Errorf("rule %s replacement = %q, want %q", rc.ID, rc.Replacement, tt.replacement)
				}
			}
		})
	}
}

func TestPIIPresets_BodyTargetOnly(t *testing.T) {
	presetNames := []string{
		PresetCreditCard,
		PresetJapanMyNumber,
		PresetEmail,
		PresetJapanPhone,
	}

	for _, name := range presetNames {
		p, err := LookupPreset(name)
		if err != nil {
			t.Fatalf("lookup %s: %v", name, err)
		}
		for _, rc := range p.Rules {
			if len(rc.Targets) != 1 || rc.Targets[0] != TargetBody {
				t.Errorf("rule %s: targets = %v, want [body]", rc.ID, rc.Targets)
			}
		}
	}
}

func TestPIIPresets_EngineIntegration_CreditCard(t *testing.T) {
	e := mustEngine(t, Config{
		OutputRules: []RuleConfig{
			{Preset: PresetCreditCard, Action: "mask"},
		},
	})

	tests := []struct {
		name string
		data string
		want string
	}{
		{
			"separated visa",
			"card: 4111-1111-1111-1111",
			"card: [MASKED:credit_card]",
		},
		{
			"separated spaces",
			"card: 4111 1111 1111 1111",
			"card: [MASKED:credit_card]",
		},
		{
			"continuous visa",
			"card: 4111111111111111",
			"card: [MASKED:credit_card]",
		},
		{
			"invalid luhn not masked",
			"number: 4111111111111112",
			"number: 4111111111111112",
		},
		{
			"no card numbers",
			"hello world",
			"hello world",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := e.FilterOutput([]byte(tt.data))
			if string(result.Data) != tt.want {
				t.Errorf("Data = %q, want %q", string(result.Data), tt.want)
			}
		})
	}
}

func TestPIIPresets_EngineIntegration_JapanMyNumber(t *testing.T) {
	e := mustEngine(t, Config{
		OutputRules: []RuleConfig{
			{Preset: PresetJapanMyNumber, Action: "mask"},
		},
	})

	tests := []struct {
		name string
		data string
		want string
	}{
		{
			"valid my number",
			"my number: 123456789018",
			"my number: [MASKED:my_number]",
		},
		{
			"valid with spaces",
			"id: 1234 5678 9018",
			"id: [MASKED:my_number]",
		},
		{
			"invalid check digit not masked",
			"id: 123456789012",
			"id: 123456789012",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := e.FilterOutput([]byte(tt.data))
			if string(result.Data) != tt.want {
				t.Errorf("Data = %q, want %q", string(result.Data), tt.want)
			}
		})
	}
}

func TestPIIPresets_EngineIntegration_Email(t *testing.T) {
	e := mustEngine(t, Config{
		OutputRules: []RuleConfig{
			{Preset: PresetEmail, Action: "mask"},
		},
	})

	tests := []struct {
		name string
		data string
		want string
	}{
		{
			"simple email",
			"contact: user@example.com",
			"contact: [MASKED:email]",
		},
		{
			"multiple emails",
			"from: a@b.com to: c@d.org",
			"from: [MASKED:email] to: [MASKED:email]",
		},
		{
			"no email",
			"no email here",
			"no email here",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := e.FilterOutput([]byte(tt.data))
			if string(result.Data) != tt.want {
				t.Errorf("Data = %q, want %q", string(result.Data), tt.want)
			}
		})
	}
}

func TestPIIPresets_EngineIntegration_JapanPhone(t *testing.T) {
	e := mustEngine(t, Config{
		OutputRules: []RuleConfig{
			{Preset: PresetJapanPhone, Action: "mask"},
		},
	})

	tests := []struct {
		name string
		data string
		want string
	}{
		{
			"mobile with dashes",
			"tel: 090-1234-5678",
			"tel: [MASKED:phone]",
		},
		{
			"landline",
			"tel: 03-1234-5678",
			"tel: [MASKED:phone]",
		},
		{
			"no phone",
			"hello world",
			"hello world",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := e.FilterOutput([]byte(tt.data))
			if string(result.Data) != tt.want {
				t.Errorf("Data = %q, want %q", string(result.Data), tt.want)
			}
		})
	}
}

func TestPIIPresets_ReplacementOverride(t *testing.T) {
	e := mustEngine(t, Config{
		OutputRules: []RuleConfig{
			{
				Preset:      PresetCreditCard,
				Action:      "mask",
				Replacement: "****-****-****-$4",
			},
		},
	})

	result := e.FilterOutput([]byte("card: 4111-1111-1111-1111"))
	want := "card: ****-****-****-1111"
	if string(result.Data) != want {
		t.Errorf("Data = %q, want %q", string(result.Data), want)
	}
}

func TestPIIPresets_ValidatorPropagation(t *testing.T) {
	// Verify that validators are properly propagated through engine compilation.
	e := mustEngine(t, Config{
		OutputRules: []RuleConfig{
			{Preset: PresetCreditCard, Action: "mask"},
		},
	})

	// Find the continuous rule and verify it has a validator.
	for _, r := range e.OutputRules() {
		if r.ID == "credit-card:continuous" {
			if r.Validator == nil {
				t.Error("credit-card:continuous should have a Validator")
			}
		}
		if r.ID == "credit-card:separated" {
			if r.Validator != nil {
				t.Error("credit-card:separated should not have a Validator")
			}
		}
	}
}

func TestPIIPresets_RealisticResponseBody(t *testing.T) {
	e := mustEngine(t, Config{
		OutputRules: []RuleConfig{
			{Preset: PresetCreditCard, Action: "mask"},
			{Preset: PresetEmail, Action: "mask"},
			{Preset: PresetJapanPhone, Action: "mask"},
		},
	})

	body := `{
  "user": {
    "name": "Taro Yamada",
    "email": "taro@example.com",
    "phone": "090-1234-5678",
    "card": "4111-1111-1111-1111"
  }
}`
	want := `{
  "user": {
    "name": "Taro Yamada",
    "email": "[MASKED:email]",
    "phone": "[MASKED:phone]",
    "card": "[MASKED:credit_card]"
  }
}`
	result := e.FilterOutput([]byte(body))
	if string(result.Data) != want {
		t.Errorf("Data = %q, want %q", string(result.Data), want)
	}
	if !result.Masked {
		t.Error("expected Masked to be true")
	}
	if len(result.Matches) != 3 {
		t.Errorf("expected 3 match entries, got %d", len(result.Matches))
	}
}

// findPresetRule returns the PresetRuleConfig with the given ID from the slice.
func findPresetRule(rules []PresetRuleConfig, id string) *PresetRuleConfig {
	for i := range rules {
		if rules[i].ID == id {
			return &rules[i]
		}
	}
	return nil
}

// compilePIIPattern compiles a regex pattern for PII testing.
func compilePIIPattern(t *testing.T, pattern string) *regexp.Regexp {
	t.Helper()
	re, err := regexp.Compile(pattern)
	if err != nil {
		t.Fatalf("compile pattern %q: %v", pattern, err)
	}
	return re
}
