; Everything javascript/identifiers.scm captures, plus TypeScript's type-level names: interface,
; type alias, enum and generic parameter names ("type_identifier"). The pinned grammar's
; node-type vocabulary has no separate "field_identifier"; a class field name is a plain
; "property_identifier", already covered below.
(identifier) @identifier
(property_identifier) @identifier
(shorthand_property_identifier) @identifier
(shorthand_property_identifier_pattern) @identifier
(private_property_identifier) @identifier
(statement_identifier) @identifier
(type_identifier) @identifier
