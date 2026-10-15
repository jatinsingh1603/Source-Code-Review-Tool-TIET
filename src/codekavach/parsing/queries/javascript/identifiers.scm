; Every identifier-typed node JavaScript's grammar has: plain references and definitions,
; object/class property names, shorthand property names (both the expression and the pattern
; form), private "#" fields, and statement labels.
(identifier) @identifier
(property_identifier) @identifier
(shorthand_property_identifier) @identifier
(shorthand_property_identifier_pattern) @identifier
(private_property_identifier) @identifier
(statement_identifier) @identifier
