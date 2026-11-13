An LLM answer the output defence rejects (for example one that leaks the request canary) is no longer stored in the response cache, so a later scan cannot replay it past a fresh canary.
