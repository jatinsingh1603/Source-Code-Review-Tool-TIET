package pay

import (
	"errors"
	"fmt"
)

type LimitError struct {
	Limit int64
}

func (e *LimitError) Error() string {
	return fmt.Sprintf("limit %d exceeded", e.Limit)
}

func check(amount int64) error {
	if amount > 100 {
		return fmt.Errorf("check: %w", &LimitError{Limit: 100})
	}
	return errors.New("ok")
}
