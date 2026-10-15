; String content only, never the quotes or a template literal's "${...}" substitution: a plain
; string and a template literal's static parts (its quasis) are both "string_fragment" nodes in
; this grammar; template_substitution holds real expressions and is deliberately not matched.
; A regex literal's pattern is captured too, so it can be classified "regex" by context.
(string_fragment) @string_content
(regex_pattern) @string_content
