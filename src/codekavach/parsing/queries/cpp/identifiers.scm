; "identifier" (values, functions, macros), "type_identifier" (types, typedefs),
; "field_identifier" (struct members and "->" fields) and "statement_identifier" (a goto label).
(identifier) @identifier
(type_identifier) @identifier
(field_identifier) @identifier
(statement_identifier) @identifier
; plus "namespace_identifier": a namespace or the scope of a qualified name.
(namespace_identifier) @identifier
