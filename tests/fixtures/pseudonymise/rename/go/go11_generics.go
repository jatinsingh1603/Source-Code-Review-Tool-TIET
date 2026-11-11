package util

func Project[Entry any, Result any](entries []Entry, mapper func(Entry) Result) []Result {
	out := make([]Result, 0, len(entries))
	for _, entry := range entries {
		out = append(out, mapper(entry))
	}
	return out
}
