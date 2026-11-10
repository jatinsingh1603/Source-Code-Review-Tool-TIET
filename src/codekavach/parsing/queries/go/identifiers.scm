; Every name node Go's grammar has: variables and functions are "identifier", types are
; "type_identifier", struct fields, methods and selector fields are "field_identifier", a package
; name is "package_identifier" and a statement label is "label_name". The blank identifier "_" is
; its own node type and is not a name.
(identifier) @identifier
(type_identifier) @identifier
(field_identifier) @identifier
(package_identifier) @identifier
(label_name) @identifier
