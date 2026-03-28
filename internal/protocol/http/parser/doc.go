// Package parser implements an independent HTTP/1.x request and response parser.
//
// This parser replaces net/http.ReadRequest and net/http.ReadResponse with
// a purpose-built implementation for security assessment. Key differences from
// the standard library:
//
//   - Headers preserve original case and order ([]RawHeader instead of map)
//   - Chunked Transfer-Encoding is decoded — the chunk markers are stripped and
//     the plain body data is returned via the Body io.Reader
//   - Content-Encoding (gzip, etc.) is NOT decompressed
//   - Invalid requests are NOT rejected — they are parsed and anomalies reported
//   - Raw bytes are captured simultaneously during parsing
//   - HTTP Request Smuggling patterns (CL/TE conflicts) are detected as Anomalies
//
// The parser outputs RawRequest and RawResponse types that carry the structured
// L7 view alongside the raw wire bytes, following the L7-first, L4-capable
// architecture principle.
package parser
