package tools

import "reflect"

type Account struct {
	FestivalBonus int64
}

func read(target Account) any {
	return reflect.ValueOf(target).FieldByName("FestivalBonus").Interface()
}
