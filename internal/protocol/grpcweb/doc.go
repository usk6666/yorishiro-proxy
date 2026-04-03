// Package grpcweb implements gRPC-Web frame parsing for the yorishiro-proxy.
//
// gRPC-Web uses the same 5-byte Length-Prefixed Message framing as standard
// gRPC, but with two key differences:
//
//  1. Base64 encoding: Content-Type "application/grpc-web-text" uses base64
//     encoding over the wire. The body must be decoded before frame parsing.
//
//  2. Embedded trailers: Trailers are sent as a final frame within the response
//     body (not as HTTP/2 trailers). The trailer frame is identified by the MSB
//     of the first byte being set (0x80). The trailer payload contains
//     key-value pairs in HTTP header format ("key: value\r\n").
//
// Wire format (per frame):
//
//	1 byte:  Flags (bit 0 = compressed, bit 7 = trailer frame)
//	4 bytes: Length (big-endian uint32)
//	N bytes: Payload (protobuf data or trailer text)
//
// Supported Content-Types:
//
//	application/grpc-web          — binary framing
//	application/grpc-web+proto    — binary framing (protobuf)
//	application/grpc-web+json     — binary framing (JSON)
//	application/grpc-web-text          — base64 encoded
//	application/grpc-web-text+proto    — base64 encoded (protobuf)
//	application/grpc-web-text+json     — base64 encoded (JSON)
//
// See: https://github.com/grpc/grpc/blob/master/doc/PROTOCOL-WEB.md
package grpcweb
