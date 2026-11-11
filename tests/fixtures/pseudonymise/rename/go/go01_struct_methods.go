package pay

import (
	"fmt"

	h "github.com/bank/helper"
)

type Account struct {
	FestivalBonus int64
	owner         string
}

func (a *Account) Accrue(rate int64) int64 {
	fmt.Println(a.FestivalBonus)
	h.Log(rate)
	return a.FestivalBonus * rate
}
