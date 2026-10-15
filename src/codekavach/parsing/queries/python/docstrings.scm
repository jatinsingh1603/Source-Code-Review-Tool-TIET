; A module, class or function docstring: a bare string expression statement in the first
; position of the module or a block. The "." anchor means "no preceding sibling"; tree-sitter
; treats a comment (an "extra" node) as transparent to this anchor, so a comment before the
; docstring does not defeat the match.
(module . (expression_statement (string) @docstring))
(block . (expression_statement (string) @docstring))
