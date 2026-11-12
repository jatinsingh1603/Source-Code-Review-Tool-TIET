; Ruby names: locals and methods are "identifier", classes and constants "constant"; an
; instance, class or global variable and a symbol carry their sigil in the node text, and the
; renamer keeps it. A hash key written "key:" is "hash_key_symbol".
(identifier) @identifier
(constant) @identifier
(instance_variable) @identifier
(class_variable) @identifier
(global_variable) @identifier
(simple_symbol) @identifier
(hash_key_symbol) @identifier
