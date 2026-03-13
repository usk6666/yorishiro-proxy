package safety

// Built-in PII (Personally Identifiable Information) output filter preset names.
const (
	PresetCreditCard    = "credit-card"
	PresetJapanMyNumber = "japan-my-number"
	PresetEmail         = "email"
	PresetJapanPhone    = "japan-phone"
)

// creditCardRules defines rules that detect credit card numbers.
var creditCardRules = []PresetRuleConfig{
	{
		ID:          "credit-card:separated",
		Name:        "Credit card number (separated)",
		Pattern:     `\b(\d{4})[-\s](\d{4})[-\s](\d{4})[-\s](\d{4})\b`,
		Targets:     []Target{TargetBody},
		Replacement: "[MASKED:credit_card]",
	},
	{
		ID:          "credit-card:continuous",
		Name:        "Credit card number (continuous)",
		Pattern:     `\b(\d{13,19})\b`,
		Targets:     []Target{TargetBody},
		Replacement: "[MASKED:credit_card]",
		Validator:   luhnValid,
	},
}

// japanMyNumberRules defines rules that detect Japanese My Number (individual number).
var japanMyNumberRules = []PresetRuleConfig{
	{
		ID:          "japan-my-number:standard",
		Name:        "My Number (12 digits)",
		Pattern:     `\b(\d{4})\s?(\d{4})\s?(\d{4})\b`,
		Targets:     []Target{TargetBody},
		Replacement: "[MASKED:my_number]",
		Validator:   myNumberValid,
	},
}

// emailRules defines rules that detect email addresses.
var emailRules = []PresetRuleConfig{
	{
		ID:          "email:standard",
		Name:        "Email address",
		Pattern:     `[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}`,
		Targets:     []Target{TargetBody},
		Replacement: "[MASKED:email]",
	},
}

// japanPhoneRules defines rules that detect Japanese phone numbers.
var japanPhoneRules = []PresetRuleConfig{
	{
		ID:          "japan-phone:mobile",
		Name:        "Japanese mobile phone number",
		Pattern:     `0[789]0[-\s]?\d{4}[-\s]?\d{4}`,
		Targets:     []Target{TargetBody},
		Replacement: "[MASKED:phone]",
	},
	{
		ID:          "japan-phone:landline",
		Name:        "Japanese landline phone number",
		Pattern:     `0\d{1,4}[-\s]?\d{1,4}[-\s]?\d{4}`,
		Targets:     []Target{TargetBody},
		Replacement: "[MASKED:phone]",
	},
}

// luhnValid returns true if match represents a valid credit card number
// according to the Luhn algorithm.
func luhnValid(match []byte) bool {
	// Extract digits from the match.
	digits := make([]int, 0, len(match))
	for _, b := range match {
		if b >= '0' && b <= '9' {
			digits = append(digits, int(b-'0'))
		}
	}
	if len(digits) < 13 || len(digits) > 19 {
		return false
	}
	return luhnCheck(digits)
}

// luhnCheck implements the Luhn algorithm for a slice of digits.
func luhnCheck(digits []int) bool {
	sum := 0
	odd := len(digits) % 2
	for i, d := range digits {
		if i%2 == odd {
			d *= 2
			if d > 9 {
				d -= 9
			}
		}
		sum += d
	}
	return sum%10 == 0
}

// myNumberValid returns true if match represents a valid Japanese My Number
// (12-digit individual number) with a correct check digit.
func myNumberValid(match []byte) bool {
	// Extract digits from the match (may contain spaces).
	digits := make([]int, 0, 12)
	for _, b := range match {
		if b >= '0' && b <= '9' {
			digits = append(digits, int(b-'0'))
		}
	}
	if len(digits) != 12 {
		return false
	}
	return myNumberCheckDigit(digits)
}

// myNumberCheckDigit validates the check digit of a 12-digit My Number.
// The check digit is the last digit. The algorithm uses weights applied
// to the first 11 digits, as specified by the Japanese government.
func myNumberCheckDigit(digits []int) bool {
	// Weights for positions 1-11 (q_n values).
	// Position n (1-based from the right, excluding check digit):
	//   q_n = (n + 1) for n <= 6
	//   q_n = (n - 5) for n >= 7
	// But digits are given left-to-right, so we reverse the index.
	sum := 0
	for i := 0; i < 11; i++ {
		p := 11 - i // position from right (1-based, excluding check digit)
		var q int
		if p <= 6 {
			q = p + 1
		} else {
			q = p - 5
		}
		sum += digits[i] * q
	}
	remainder := sum % 11
	var expected int
	if remainder <= 1 {
		expected = 0
	} else {
		expected = 11 - remainder
	}
	return digits[11] == expected
}

func init() {
	presets[PresetCreditCard] = Preset{
		Name:  PresetCreditCard,
		Rules: creditCardRules,
	}
	presets[PresetJapanMyNumber] = Preset{
		Name:  PresetJapanMyNumber,
		Rules: japanMyNumberRules,
	}
	presets[PresetEmail] = Preset{
		Name:  PresetEmail,
		Rules: emailRules,
	}
	presets[PresetJapanPhone] = Preset{
		Name:  PresetJapanPhone,
		Rules: japanPhoneRules,
	}
}
