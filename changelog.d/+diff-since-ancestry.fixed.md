`codekavach scan --diff-since` accepts ancestry steps such as `HEAD~1` and `main^2`; before, they failed the plain-ref check and the whole tree was scanned.
