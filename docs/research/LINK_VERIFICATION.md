# Link verification log

Every URL in `REFERENCE.md`, `RESOURCE.md` and `docs/research/INSIGHTS.md` was requested on 2026-09-21 before these files were published. This log records the outcome so that a reader can spot-check the survey and so that the check can be repeated before the research paper is submitted.

## Method

1. All distinct URLs were extracted from the three files (1578 URLs).
2. Each was requested with a desktop browser user agent, following redirects, with a 25 second timeout.
3. `doi.org` links that ended at a publisher's bot protection were verified against the DOI registry instead (`https://doi.org/api/handles/<doi>`, response code 1 means the DOI is registered).
4. Anything that still failed was retried individually; links that could not be verified were removed from the files.

During compilation each entry was also checked by a second, independent pass that confirmed title, authors, year, venue and licence against the landing page.

## Result

| Outcome | Count |
|---|---|
| HTTP 200 on first request | 1420 |
| `doi.org` links, all confirmed registered through the DOI registry API | 130 |
| HTTP 403 from publisher or standards-body bot protection (page exists; opens in a browser) | 21 |
| Failed on first pass, succeeded on individual retry (rate limiting or transient) | 5 |
| Could not be verified and therefore removed | 2 |

Hosts that answer automated requests with HTTP 403 (open these in a browser to check): www.iso.org (12), misra.org.uk (2), openai.com (2), www.gao.gov (2), cppcheck.sourceforge.io (1), ithandbook.ffiec.gov (1), www.bloomberg.com (1).

Removed links: a deep link to a PDF on indiacode.nic.in that did not respond within 60 seconds (the row keeps its verified primary source), and a vendor product page on opentext.com that refuses automated clients.

## Known link hazards found during the survey

- OWASP moved project pages from `owasp.org/www-project-*` to `owasp.org/projects/*`. Some well-known older URLs now return 404. Use the URLs in `REFERENCE.md`.
- The SEI CERT coding standards moved from the Confluence wiki to `cmu-sei.github.io/secure-coding-standards`. Citations to `wiki.sei.cmu.edu` will rot.
- The OWASP Code Review Guide repository was archived in April 2025; version 2.0 is the citable edition.

## Repeating the check

```bash
grep -ohE 'https?://[^ )>\]|"`]+' REFERENCE.md RESOURCE.md docs/research/INSIGHTS.md | sed -E 's/[.,;:]+$//' | sort -u > urls.txt
xargs -P 16 -I{} curl -sL -o /dev/null -w '%{http_code} {}
' --max-time 25 -A 'Mozilla/5.0' {} < urls.txt | sort | grep -v '^200 '
```

URLs that contain parentheses must be checked by hand, because the pattern above cuts them short.
