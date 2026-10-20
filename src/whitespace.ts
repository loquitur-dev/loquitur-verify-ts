// The whitespace set W, shared by every check that asks whether a string is empty.
//
// W is U+0009-U+000D, U+001C-U+001F, U+0020, U+0085, U+00A0, U+1680, U+2000-U+200A, U+2028,
// U+2029, U+202F, U+205F, U+3000 and U+FEFF: the union of what ECMAScript's trim() and Python's
// str.strip() remove, written out so neither language's definition decides. It is used only to
// ask whether a value is empty, never to change one: a compared value is compared as written.

function isWhitespaceW(codePoint: number): boolean {
  return (codePoint >= 0x09 && codePoint <= 0x0d) || (codePoint >= 0x1c && codePoint <= 0x20)
    || codePoint === 0x85 || codePoint === 0xa0 || codePoint === 0x1680
    || (codePoint >= 0x2000 && codePoint <= 0x200a) || codePoint === 0x2028 || codePoint === 0x2029
    || codePoint === 0x202f || codePoint === 0x205f || codePoint === 0x3000 || codePoint === 0xfeff;
}

/** A string with at least one code point outside W. */
export function nonBlankString(v: unknown): v is string {
  if (typeof v !== "string") return false;
  for (const ch of v) if (!isWhitespaceW(ch.codePointAt(0)!)) return true;
  return false;
}
