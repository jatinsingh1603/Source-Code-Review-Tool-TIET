package loans

import (
	"database/sql"
	"fmt"
)

type Disbursement struct {
	FestivalBonus int64  `json:"festivalBonus" db:"festival_bonus"`
	BorrowerRef   string `json:"borrowerRef"`
}

func (d *Disbursement) Disburse(db *sql.DB) (int64, error) {
	var limit int64
	row := db.QueryRow("select limit_amount from loans where ref = ?", d.BorrowerRef)
	if err := row.Scan(&limit); err != nil {
		return 0, fmt.Errorf("disburse %s: %w", d.BorrowerRef, err)
	}
	return limit + d.FestivalBonus, nil
}
