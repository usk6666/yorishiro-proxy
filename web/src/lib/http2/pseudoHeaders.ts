/**
 * HTTP/2 pseudo-header constants and helpers (RFC 9113 §8.3).
 *
 * Pseudo-headers (`:method`, `:path`, `:authority`, `:scheme`, `:status`) are
 * a protocol-format concept distinct from regular headers — they carry
 * request-line / status-line information in HTTP/2's HEADERS frames. Tools
 * that consume HTTP-shaped output (curl, HAR validators) reject them when
 * they appear as ordinary headers, so export sinks must filter them.
 *
 * This module is the single source of truth for that set.
 */

/** HTTP/2 request pseudo-header names. */
export const REQUEST_PSEUDO_HEADERS = [
  ":method",
  ":path",
  ":authority",
  ":scheme",
];

/** HTTP/2 response pseudo-header names. */
export const RESPONSE_PSEUDO_HEADERS = [":status"];

/** All HTTP/2 pseudo-header names. */
export const ALL_PSEUDO_HEADERS = new Set<string>([
  ...REQUEST_PSEUDO_HEADERS,
  ...RESPONSE_PSEUDO_HEADERS,
]);

/** Check if a header name is an HTTP/2 pseudo-header (case-insensitive). */
export function isPseudoHeader(name: string): boolean {
  return ALL_PSEUDO_HEADERS.has(name.toLowerCase());
}
