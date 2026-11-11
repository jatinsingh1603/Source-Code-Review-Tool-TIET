package pay

type Mandate struct {
	NachReference string `json:"nachReference,omitempty" db:"nach_reference"`
	Limit         int64  `json:"limit" validate:"required,min=3" gorm:"column:limit_amount;primaryKey"`
	Internal      string `json:"-"`
	Odd           string `custom:"festival-bonus"`
}
