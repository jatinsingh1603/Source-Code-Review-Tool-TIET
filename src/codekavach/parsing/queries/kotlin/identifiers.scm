; Kotlin's grammar has no field names. Names are "simple_identifier" (values, functions,
; parameters, members), "type_identifier" (types and import aliases) and "interpolated_identifier"
; (a "$name" inside a string template).
(simple_identifier) @identifier
(type_identifier) @identifier
(interpolated_identifier) @identifier
