; Every identifier occurrence in Python: Python's grammar uses one node type for every name
; (definitions, references, parameters, attributes, keyword-argument names, aliases, match
; targets, global/nonlocal names). Capturing by node type, not by syntactic position, is what
; keeps this exhaustive as the grammar grows.
(identifier) @identifier
