package pay

import _ "github.com/lib/pq"

func ignore(festivalBonus int64) {
	_ = festivalBonus
	for _, step := range []int64{1, 2} {
		_ = step
	}
}
