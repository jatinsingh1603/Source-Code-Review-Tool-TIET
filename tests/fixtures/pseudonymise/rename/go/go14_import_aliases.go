package web

import (
	"encoding/json"
	log "github.com/sirupsen/logrus"
	"github.com/bank/payments/internal/rules"
)

func encode(value any) []byte {
	out, err := json.Marshal(value)
	if err != nil {
		log.Error(err)
	}
	rules.Check(out)
	return out
}
