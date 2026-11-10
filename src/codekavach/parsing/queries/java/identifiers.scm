; Every name node Java's grammar has: a variable, field, method or package name is an
; "identifier" and a type name is a "type_identifier". Keywords such as "this" and "super" are
; their own node types and are not names.
(identifier) @identifier
(type_identifier) @identifier
