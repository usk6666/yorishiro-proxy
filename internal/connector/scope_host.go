package connector

// Host comparison form for TargetScope (USK-1129, USK-1250).
//
// A TargetScope rule names a host; a data-path gate hands CheckTarget the
// host exactly as the client spelled it, and the dialer (or a libc
// resolver, or an upstream proxy) may read several spellings as the same
// destination. Each spelling the dial treats as the denied host must
// therefore compare equal to it, or the deny is bypassed while the
// connection still lands on the denied host. The comparison form is
// hostcanon.Fold (the deny-like form; see package internal/hostcanon). The
// folding is comparison-only: dial targets, CONNECT replies, Host headers,
// recorded flows and stored rules all stay verbatim (MITM Principle 1).

// numericHostReason is CheckTarget's reason for the fail-closed numeric
// host case (see hostcanon.NumericUnparsable).
const numericHostReason = "blocked: host ends in a number but is not a valid IPv4 address"

// unspecifiedHostReason is CheckTarget's reason for the fail-closed empty
// or unspecified dial host case (see hostcanon.UnspecifiedOrEmpty).
const unspecifiedHostReason = "blocked: empty or unspecified host (0.0.0.0 / ::) dials the proxy host; use an explicit address such as 127.0.0.1"

// legacyIPv4Reason is CheckTarget's reason for the fail-closed
// non-canonical IPv4 dial host case (see hostcanon.LegacyIPv4Spelling).
const legacyIPv4Reason = "blocked: non-canonical IPv4 spelling (integer, hex, octal or short form) is read as an address by some resolvers and looked up in DNS by others; use the dotted-decimal address such as 127.0.0.1"
