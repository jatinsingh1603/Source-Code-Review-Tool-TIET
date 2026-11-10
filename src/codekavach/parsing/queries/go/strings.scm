; String content only, never the quotes or backticks: an interpreted string is a run of
; "interpreted_string_literal_content" nodes with escape sequences between them, a raw string one
; "raw_string_literal_content" node. Import paths are strings too, and are kept so the literal
; classifier can see them.
(interpreted_string_literal_content) @string_content
(raw_string_literal_content) @string_content
