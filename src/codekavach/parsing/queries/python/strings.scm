; String content only, never the delimiters or an f-string's interpolation: every Python string
; (plain, raw, byte, or an f-string's literal segments) decomposes into string_start,
; string_content (one per literal segment) and string_end; the interpolation node holds real
; expressions and is deliberately not matched here.
(string_content) @string_content
