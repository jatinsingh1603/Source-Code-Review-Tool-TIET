; String content only, never the quotes: a plain string is a run of "string_fragment" nodes and a
; text block a run of "multiline_string_fragment" nodes, with escape sequences between them.
(string_fragment) @string_content
(multiline_string_fragment) @string_content
