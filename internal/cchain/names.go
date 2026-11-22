package cchain

import (
	"unicode"
	"unicode/utf8"

	"golang.org/x/text/unicode/norm"

	"github.com/rerouteholdings/rerouted/internal/wire"
)

// The text rules for the community's readable name and description (SPEC §16.2.3, §16.4).
// Channel and role names are sealed, so validity never depends on them (§16.2.4).

const (
	maxNameLen = 64  // code points
	maxDescLen = 300 // code points
)

// bidiControl reports the bidirectional embeddings, overrides, and isolates.
func bidiControl(r rune) bool {
	return r >= 0x202A && r <= 0x202E || r >= 0x2066 && r <= 0x2069
}

// zeroWidth reports the zero-width characters names can't hold.
func zeroWidth(r rune) bool {
	return r >= 0x200B && r <= 0x200D || r == 0x2060 || r == 0xFEFF
}

// validName applies §16.4's name rules: 1 to 64 code points, NFC, no control characters,
// no bidirectional overrides, no zero-width characters, no Extended_Pictographic
// characters, and no leading or trailing whitespace.
func validName(s string) bool {
	if !utf8.ValidString(s) || !norm.NFC.IsNormalString(s) {
		return false
	}
	n := utf8.RuneCountInString(s)
	if n < 1 || n > maxNameLen {
		return false
	}
	first, _ := utf8.DecodeRuneInString(s)
	last, _ := utf8.DecodeLastRuneInString(s)
	if unicode.IsSpace(first) || unicode.IsSpace(last) {
		return false
	}
	for _, r := range s {
		if unicode.IsControl(r) || bidiControl(r) || zeroWidth(r) || extPict(r) {
			return false
		}
	}
	return true
}

// validDesc applies §16.2.3's description rules: at most 300 code points, NFC, no
// control characters other than line feed, and no bidirectional overrides.
func validDesc(s string) bool {
	if !utf8.ValidString(s) || !norm.NFC.IsNormalString(s) || utf8.RuneCountInString(s) > maxDescLen {
		return false
	}
	for _, r := range s {
		if (unicode.IsControl(r) && r != '\n') || bidiControl(r) {
			return false
		}
	}
	return true
}

// validServerName: a lowercase DNS name of at least two labels, never an IP literal (§5.1).
func validServerName(s string) bool { return wire.ValidServerName(s) }

// extPict reports Unicode's Extended_Pictographic property (emoji-data.txt). The property
// is stable: its unassigned ranges are reserved for pictographs, so this table doesn't
// change with new emoji.
func extPict(r rune) bool {
	if r < 0xA9 {
		return false
	}
	lo, hi := 0, len(extPictRanges)
	for lo < hi {
		m := (lo + hi) / 2
		switch {
		case r < extPictRanges[m][0]:
			hi = m
		case r > extPictRanges[m][1]:
			lo = m + 1
		default:
			return true
		}
	}
	return false
}

var extPictRanges = [][2]rune{
	{0x00A9, 0x00A9}, {0x00AE, 0x00AE}, {0x203C, 0x203C}, {0x2049, 0x2049}, {0x2122, 0x2122},
	{0x2139, 0x2139}, {0x2194, 0x2199}, {0x21A9, 0x21AA}, {0x231A, 0x231B}, {0x2328, 0x2328},
	{0x2388, 0x2388}, {0x23CF, 0x23CF}, {0x23E9, 0x23F3}, {0x23F8, 0x23FA}, {0x24C2, 0x24C2},
	{0x25AA, 0x25AB}, {0x25B6, 0x25B6}, {0x25C0, 0x25C0}, {0x25FB, 0x25FE}, {0x2600, 0x2605},
	{0x2607, 0x2612}, {0x2614, 0x2685}, {0x2690, 0x2705}, {0x2708, 0x2712}, {0x2714, 0x2714},
	{0x2716, 0x2716}, {0x271D, 0x271D}, {0x2721, 0x2721}, {0x2728, 0x2728}, {0x2733, 0x2734},
	{0x2744, 0x2744}, {0x2747, 0x2747}, {0x274C, 0x274C}, {0x274E, 0x274E}, {0x2753, 0x2755},
	{0x2757, 0x2757}, {0x2763, 0x2767}, {0x2795, 0x2797}, {0x27A1, 0x27A1}, {0x27B0, 0x27B0},
	{0x27BF, 0x27BF}, {0x2934, 0x2935}, {0x2B05, 0x2B07}, {0x2B1B, 0x2B1C}, {0x2B50, 0x2B50},
	{0x2B55, 0x2B55}, {0x3030, 0x3030}, {0x303D, 0x303D}, {0x3297, 0x3297}, {0x3299, 0x3299},
	{0x1F000, 0x1F0FF}, {0x1F10D, 0x1F10F}, {0x1F12F, 0x1F12F}, {0x1F16C, 0x1F171},
	{0x1F17E, 0x1F17F}, {0x1F18E, 0x1F18E}, {0x1F191, 0x1F19A}, {0x1F1AD, 0x1F1E5},
	{0x1F201, 0x1F20F}, {0x1F21A, 0x1F21A}, {0x1F22F, 0x1F22F}, {0x1F232, 0x1F23A},
	{0x1F23C, 0x1F23F}, {0x1F249, 0x1F3FA}, {0x1F400, 0x1F53D}, {0x1F546, 0x1F64F},
	{0x1F680, 0x1F6FF}, {0x1F774, 0x1F77F}, {0x1F7D5, 0x1F7FF}, {0x1F80C, 0x1F80F},
	{0x1F848, 0x1F84F}, {0x1F85A, 0x1F85F}, {0x1F888, 0x1F88F}, {0x1F8AE, 0x1F8FF},
	{0x1F90C, 0x1F93A}, {0x1F93C, 0x1F945}, {0x1F947, 0x1FAFF}, {0x1FC00, 0x1FFFD},
}
