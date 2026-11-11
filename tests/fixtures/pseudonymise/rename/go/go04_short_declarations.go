package pay

import "strconv"

func parse(raw string) (int64, error) {
	value, err := strconv.ParseInt(raw, 10, 64)
	if err != nil {
		return 0, err
	}
	doubled, _ := strconv.Atoi(raw)
	return value + int64(doubled), nil
}
