package scan

import "strings"

// zeroWidthCodepoints are stripped entirely before injection-pattern
// matching -- each is invisible to a human reader but would otherwise
// split an otherwise-matching phrase across a regex's word boundaries
// (issue #11 story 13).
var zeroWidthCodepoints = map[rune]bool{
	0x200B: true, // zero-width space
	0x200C: true, // zero-width non-joiner
	0x200D: true, // zero-width joiner
	0xFEFF: true, // byte order mark / zero-width no-break space
	0x2060: true, // word joiner
}

// homoglyphs maps commonly-confused lookalike characters (Cyrillic and
// Greek letters visually indistinguishable from Latin ones, plus
// fullwidth Latin) to their plain-Latin equivalent (issue #11 story 12).
// Deliberately a curated, small set of the confusables actually used in
// real-world prompt-injection evasion attempts, not an exhaustive
// Unicode confusables table -- broad coverage risks false-normalizing
// genuinely non-Latin text into nonsense.
var homoglyphs = map[rune]rune{
	// Cyrillic lookalikes for Latin letters.
	'а': 'a', 'А': 'A', // U+0430, U+0410
	'е': 'e', 'Е': 'E', // U+0435, U+0415
	'о': 'o', 'О': 'O', // U+043E, U+041E
	'р': 'p', 'Р': 'P', // U+0440, U+0420
	'с': 'c', 'С': 'C', // U+0441, U+0421
	'х': 'x', 'Х': 'X', // U+0445, U+0425
	'у': 'y', 'У': 'Y', // U+0443, U+0423
	'і': 'i', 'І': 'I', // U+0456, U+0406 (Ukrainian/Belarusian i)
	// Greek lookalikes.
	'ο': 'o', 'Ο': 'O', // U+03BF, U+039F (omicron)
	'ρ': 'p', 'Ρ': 'P', // U+03C1, U+03A1 (rho)
	'α': 'a', 'Α': 'A', // U+03B1, U+0391 (alpha)
}

func init() {
	// Fullwidth Latin (U+FF21-FF3A upper, U+FF41-FF5A lower) maps
	// mechanically onto plain ASCII Latin, one codepoint offset apart --
	// generated rather than listed by hand.
	for r := rune('A'); r <= 'Z'; r++ {
		homoglyphs[r-'A'+0xFF21] = r
	}
	for r := rune('a'); r <= 'z'; r++ {
		homoglyphs[r-'a'+0xFF41] = r
	}
}

// normalizeForDetection returns a copy of body with known zero-width
// codepoints removed and known homoglyphs mapped to their plain-Latin
// equivalent -- used only to decide whether a pattern matches, never as
// a replacement for the real body. Callers must keep scanning/returning
// the original bytes; this function's output exists purely to make
// evasion via invisible characters or lookalike letters not work.
func normalizeForDetection(body []byte) []byte {
	var b strings.Builder
	b.Grow(len(body))
	for _, r := range string(body) {
		if zeroWidthCodepoints[r] {
			continue
		}
		if mapped, ok := homoglyphs[r]; ok {
			r = mapped
		}
		b.WriteRune(r)
	}
	return []byte(b.String())
}
