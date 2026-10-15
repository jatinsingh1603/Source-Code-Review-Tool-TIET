; "#" comments only. Docstrings are a string expression statement, not a comment node in this
; grammar; codekavach.parsing.specs.python reclassifies them into comments() separately, because
; that decision needs the statement's position in its block, not just its node type.
(comment) @comment
