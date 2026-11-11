package data

import "database/sql"

func balanceOf(db *sql.DB, accountRef string) (int64, error) {
	rows, err := db.Query("select balance from accounts where ref = ?", accountRef)
	if err != nil {
		return 0, err
	}
	defer rows.Close()
	var balance int64
	for rows.Next() {
		if err := rows.Scan(&balance); err != nil {
			return 0, err
		}
	}
	return balance, nil
}
