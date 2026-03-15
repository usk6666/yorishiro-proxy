package hpack

import (
	"errors"
)

// ErrInvalidHuffman is returned when Huffman-coded data is invalid.
var ErrInvalidHuffman = errors.New("hpack: invalid Huffman-coded data")

// huffmanCode stores the Huffman code and bit length for each symbol (0-256).
// Symbol 256 is EOS.
type huffmanCode struct {
	code uint32
	bits uint8
}

// huffmanEncode encodes src using the Huffman coding table from RFC 7541
// Appendix B.
func huffmanEncode(dst, src []byte) []byte {
	var bits uint64
	var nbits uint8
	for _, b := range src {
		c := huffmanCodes[b]
		bits = bits<<c.bits | uint64(c.code)
		nbits += c.bits
		for nbits >= 8 {
			nbits -= 8
			dst = append(dst, byte(bits>>nbits))
		}
	}
	// Pad with EOS prefix (all 1s) to byte boundary.
	if nbits > 0 {
		bits <<= 8 - nbits
		bits |= (1 << (8 - nbits)) - 1
		dst = append(dst, byte(bits))
	}
	return dst
}

// huffmanEncodedLen returns the number of bytes needed to Huffman-encode src.
func huffmanEncodedLen(src []byte) int {
	var bits uint64
	for _, b := range src {
		bits += uint64(huffmanCodes[b].bits)
	}
	return int((bits + 7) / 8)
}

// huffmanDecodeState holds mutable state for Huffman decoding.
type huffmanDecodeState struct {
	node          *huffmanTreeNode
	paddingBits   uint8
	allOnePadding bool
}

// walkBit advances the Huffman tree by one bit. It returns the decoded byte
// and true if a symbol was emitted, or 0 and false otherwise.
// It returns an error if the tree walk reaches a nil node or the EOS symbol.
func (s *huffmanDecodeState) walkBit(bit uint64) (byte, bool, error) {
	s.paddingBits++
	if bit == 0 {
		s.allOnePadding = false
		s.node = s.node.left
	} else {
		s.node = s.node.right
	}
	if s.node == nil {
		return 0, false, ErrInvalidHuffman
	}
	if s.node.sym != 0 || s.node.leaf {
		if s.node.sym == 256 {
			return 0, false, ErrInvalidHuffman
		}
		sym := byte(s.node.sym)
		s.node = &huffmanTree
		s.paddingBits = 0
		s.allOnePadding = true
		return sym, true, nil
	}
	return 0, false, nil
}

// validatePadding checks EOS padding per RFC 7541 Section 5.2:
// - Padding MUST consist of the most-significant bits of EOS (all 1s).
// - Padding of more than 7 bits MUST be treated as a decoding error.
func (s *huffmanDecodeState) validatePadding() error {
	if s.node != &huffmanTree {
		if s.paddingBits > 7 || !s.allOnePadding {
			return ErrInvalidHuffman
		}
	}
	return nil
}

// huffmanDecode decodes Huffman-coded data from src.
func huffmanDecode(dst, src []byte) ([]byte, error) {
	var bits uint64
	var nbits uint8
	state := huffmanDecodeState{
		node:          &huffmanTree,
		allOnePadding: true,
	}
	for _, b := range src {
		bits = bits<<8 | uint64(b)
		nbits += 8
		for nbits >= 4 {
			// Walk 4 bits at a time for efficiency.
			nbits -= 4
			idx := (bits >> nbits) & 0x0f
			for i := 3; i >= 0; i-- {
				sym, emitted, err := state.walkBit((idx >> uint(i)) & 1)
				if err != nil {
					return nil, err
				}
				if emitted {
					dst = append(dst, sym)
				}
			}
		}
	}
	// Process remaining bits.
	for nbits > 0 {
		nbits--
		sym, emitted, err := state.walkBit((bits >> nbits) & 1)
		if err != nil {
			return nil, err
		}
		if emitted {
			dst = append(dst, sym)
		}
	}
	if err := state.validatePadding(); err != nil {
		return nil, err
	}
	return dst, nil
}

// huffmanTreeNode is a binary tree node used for Huffman decoding.
type huffmanTreeNode struct {
	left  *huffmanTreeNode
	right *huffmanTreeNode
	sym   uint16
	leaf  bool
}

var huffmanTree huffmanTreeNode

func init() {
	for i, c := range huffmanCodes {
		addHuffmanNode(&huffmanTree, c.code, c.bits, uint16(i))
	}
}

func addHuffmanNode(root *huffmanTreeNode, code uint32, bits uint8, sym uint16) {
	node := root
	for i := int(bits) - 1; i >= 0; i-- {
		bit := (code >> uint(i)) & 1
		if bit == 0 {
			if node.left == nil {
				node.left = &huffmanTreeNode{}
			}
			node = node.left
		} else {
			if node.right == nil {
				node.right = &huffmanTreeNode{}
			}
			node = node.right
		}
	}
	node.sym = sym
	node.leaf = true
}

// huffmanCodes contains the Huffman code table from RFC 7541 Appendix B.
// Index is the symbol value (0-256), where 256 is EOS.
var huffmanCodes = [257]huffmanCode{
	{0x1ff8, 13},
	{0x7fffd8, 23},
	{0xfffffe2, 28},
	{0xfffffe3, 28},
	{0xfffffe4, 28},
	{0xfffffe5, 28},
	{0xfffffe6, 28},
	{0xfffffe7, 28},
	{0xfffffe8, 28},
	{0xffffea, 24},
	{0x3ffffffc, 30},
	{0xfffffe9, 28},
	{0xfffffea, 28},
	{0x3ffffffd, 30},
	{0xfffffeb, 28},
	{0xfffffec, 28},
	{0xfffffed, 28},
	{0xfffffee, 28},
	{0xfffffef, 28},
	{0xffffff0, 28},
	{0xffffff1, 28},
	{0xffffff2, 28},
	{0x3ffffffe, 30},
	{0xffffff3, 28},
	{0xffffff4, 28},
	{0xffffff5, 28},
	{0xffffff6, 28},
	{0xffffff7, 28},
	{0xffffff8, 28},
	{0xffffff9, 28},
	{0xffffffa, 28},
	{0xffffffb, 28},
	{0x14, 6},     // ' ' (32)
	{0x3f8, 10},   // '!'
	{0x3f9, 10},   // '"'
	{0xffa, 12},   // '#'
	{0x1ff9, 13},  // '$'
	{0x15, 6},     // '%'
	{0xf8, 8},     // '&'
	{0x7fa, 11},   // '\''
	{0x3fa, 10},   // '('
	{0x3fb, 10},   // ')'
	{0xf9, 8},     // '*'
	{0x7fb, 11},   // '+'
	{0xfa, 8},     // ','
	{0x16, 6},     // '-'
	{0x17, 6},     // '.'
	{0x18, 6},     // '/'
	{0x0, 5},      // '0'
	{0x1, 5},      // '1'
	{0x2, 5},      // '2'
	{0x19, 6},     // '3'
	{0x1a, 6},     // '4'
	{0x1b, 6},     // '5'
	{0x1c, 6},     // '6'
	{0x1d, 6},     // '7'
	{0x1e, 6},     // '8'
	{0x1f, 6},     // '9'
	{0x5c, 7},     // ':'
	{0xfb, 8},     // ';'
	{0x7ffc, 15},  // '<'
	{0x20, 6},     // '='
	{0xffb, 12},   // '>'
	{0x3fc, 10},   // '?'
	{0x1ffa, 13},  // '@'
	{0x21, 6},     // 'A'
	{0x5d, 7},     // 'B'
	{0x5e, 7},     // 'C'
	{0x5f, 7},     // 'D'
	{0x60, 7},     // 'E'
	{0x61, 7},     // 'F'
	{0x62, 7},     // 'G'
	{0x63, 7},     // 'H'
	{0x64, 7},     // 'I'
	{0x65, 7},     // 'J'
	{0x66, 7},     // 'K'
	{0x67, 7},     // 'L'
	{0x68, 7},     // 'M'
	{0x69, 7},     // 'N'
	{0x6a, 7},     // 'O'
	{0x6b, 7},     // 'P'
	{0x6c, 7},     // 'Q'
	{0x6d, 7},     // 'R'
	{0x6e, 7},     // 'S'
	{0x6f, 7},     // 'T'
	{0x70, 7},     // 'U'
	{0x71, 7},     // 'V'
	{0x72, 7},     // 'W'
	{0xfc, 8},     // 'X'
	{0x73, 7},     // 'Y'
	{0xfd, 8},     // 'Z'
	{0x1ffb, 13},  // '['
	{0x7fff0, 19}, // '\\'
	{0x1ffc, 13},  // ']'
	{0x3ffc, 14},  // '^'
	{0x22, 6},     // '_'
	{0x7ffd, 15},  // '`'
	{0x3, 5},      // 'a'
	{0x23, 6},     // 'b'
	{0x4, 5},      // 'c'
	{0x24, 6},     // 'd'
	{0x5, 5},      // 'e'
	{0x25, 6},     // 'f'
	{0x26, 6},     // 'g'
	{0x27, 6},     // 'h'
	{0x6, 5},      // 'i'
	{0x74, 7},     // 'j'
	{0x75, 7},     // 'k'
	{0x28, 6},     // 'l'
	{0x29, 6},     // 'm'
	{0x2a, 6},     // 'n'
	{0x7, 5},      // 'o'
	{0x2b, 6},     // 'p'
	{0x76, 7},     // 'q'
	{0x2c, 6},     // 'r'
	{0x8, 5},      // 's'
	{0x9, 5},      // 't'
	{0x2d, 6},     // 'u'
	{0x77, 7},     // 'v'
	{0x78, 7},     // 'w'
	{0x79, 7},     // 'x'
	{0x7a, 7},     // 'y'
	{0x7b, 7},     // 'z'
	{0x7ffe, 15},  // '{'
	{0x7fc, 11},   // '|'
	{0x3ffd, 14},  // '}'
	{0x1ffd, 13},  // '~'
	{0xffffffc, 28},
	{0xfffe6, 20},
	{0x3fffd2, 22},
	{0xfffe7, 20},
	{0xfffe8, 20},
	{0x3fffd3, 22},
	{0x3fffd4, 22},
	{0x3fffd5, 22},
	{0x7fffd9, 23},
	{0x3fffd6, 22},
	{0x7fffda, 23},
	{0x7fffdb, 23},
	{0x7fffdc, 23},
	{0x7fffdd, 23},
	{0x7fffde, 23},
	{0xffffeb, 24},
	{0x7fffdf, 23},
	{0xffffec, 24},
	{0xffffed, 24},
	{0x3fffd7, 22},
	{0x7fffe0, 23},
	{0xffffee, 24},
	{0x7fffe1, 23},
	{0x7fffe2, 23},
	{0x7fffe3, 23},
	{0x7fffe4, 23},
	{0x1fffdc, 21},
	{0x3fffd8, 22},
	{0x7fffe5, 23},
	{0x3fffd9, 22},
	{0x7fffe6, 23},
	{0x7fffe7, 23},
	{0xffffef, 24},
	{0x3fffda, 22},
	{0x1fffdd, 21},
	{0xfffe9, 20},
	{0x3fffdb, 22},
	{0x3fffdc, 22},
	{0x7fffe8, 23},
	{0x7fffe9, 23},
	{0x1fffde, 21},
	{0x7fffea, 23},
	{0x3fffdd, 22},
	{0x3fffde, 22},
	{0xfffff0, 24},
	{0x1fffdf, 21},
	{0x3fffdf, 22},
	{0x7fffeb, 23},
	{0x7fffec, 23},
	{0x1fffe0, 21},
	{0x1fffe1, 21},
	{0x3fffe0, 22},
	{0x1fffe2, 21},
	{0x7fffed, 23},
	{0x3fffe1, 22},
	{0x7fffee, 23},
	{0x7fffef, 23},
	{0xfffea, 20},
	{0x3fffe2, 22},
	{0x3fffe3, 22},
	{0x3fffe4, 22},
	{0x7ffff0, 23},
	{0x3fffe5, 22},
	{0x3fffe6, 22},
	{0x7ffff1, 23},
	{0x3ffffe0, 26},
	{0x3ffffe1, 26},
	{0xfffeb, 20},
	{0x7fff1, 19},
	{0x3fffe7, 22},
	{0x7ffff2, 23},
	{0x3fffe8, 22},
	{0x1ffffec, 25},
	{0x3ffffe2, 26},
	{0x3ffffe3, 26},
	{0x3ffffe4, 26},
	{0x7ffffde, 27},
	{0x7ffffdf, 27},
	{0x3ffffe5, 26},
	{0xfffff1, 24},
	{0x1ffffed, 25},
	{0x7fff2, 19},
	{0x1fffe3, 21},
	{0x3ffffe6, 26},
	{0x7ffffe0, 27},
	{0x7ffffe1, 27},
	{0x3ffffe7, 26},
	{0x7ffffe2, 27},
	{0xfffff2, 24},
	{0x1fffe4, 21},
	{0x1fffe5, 21},
	{0x3ffffe8, 26},
	{0x3ffffe9, 26},
	{0xffffffd, 28},
	{0x7ffffe3, 27},
	{0x7ffffe4, 27},
	{0x7ffffe5, 27},
	{0xfffec, 20},
	{0xfffff3, 24},
	{0xfffed, 20},
	{0x1fffe6, 21},
	{0x3fffe9, 22},
	{0x1fffe7, 21},
	{0x1fffe8, 21},
	{0x7ffff3, 23},
	{0x3fffea, 22},
	{0x3fffeb, 22},
	{0x1ffffee, 25},
	{0x1ffffef, 25},
	{0xfffff4, 24},
	{0xfffff5, 24},
	{0x3ffffea, 26},
	{0x7ffff4, 23},
	{0x3ffffeb, 26},
	{0x7ffffe6, 27},
	{0x3ffffec, 26},
	{0x3ffffed, 26},
	{0x7ffffe7, 27},
	{0x7ffffe8, 27},
	{0x7ffffe9, 27},
	{0x7ffffea, 27},
	{0x7ffffeb, 27},
	{0xffffffe, 28},
	{0x7ffffec, 27},
	{0x7ffffed, 27},
	{0x7ffffee, 27},
	{0x7ffffef, 27},
	{0x7fffff0, 27},
	{0x3ffffee, 26},
	{0x3fffffff, 30}, // EOS (256)
}
