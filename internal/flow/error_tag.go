package flow

// ErrorTagMaxLen caps the size of the err.Error() string persisted under
// Stream tags["error"] (USK-797). Stream tags are loaded into memory and
// shipped over MCP per query — a runaway nested-wrap chain or a multi-MB
// transport-layer error message must not be allowed to balloon the row.
// 1 KiB is large enough for "dial: stream error refused: ..." patterns
// (~40 chars) plus several layers of fmt.Errorf wrap context, which is
// the actionable information; anything beyond that is structural noise.
const ErrorTagMaxLen = 1024

// TruncateErrorTag returns msg, or msg truncated to ErrorTagMaxLen with a
// "...[truncated]" marker suffix when the source exceeds the cap. The cut
// walks back to a UTF-8 rune boundary so the output remains valid UTF-8
// even if the cap lands mid-rune (multi-byte runes are dropped wholesale).
//
// Shared by the live data path's OnComplete hook (proxybuild) and the MCP
// resend / fuzz Stream finalizer so both cap tags["error"] identically.
func TruncateErrorTag(msg string) string {
	if len(msg) <= ErrorTagMaxLen {
		return msg
	}
	const marker = "...[truncated]"
	if ErrorTagMaxLen <= len(marker) {
		return msg[:ErrorTagMaxLen]
	}
	cut := ErrorTagMaxLen - len(marker)
	// Walk back to a rune boundary so we don't slice in the middle of a
	// multi-byte UTF-8 sequence.
	for cut > 0 && (msg[cut]&0xC0) == 0x80 {
		cut--
	}
	return msg[:cut] + marker
}
