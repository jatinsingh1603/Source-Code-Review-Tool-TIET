package model

type Audit struct {
	CreatedBy string
}

type Loan struct {
	Audit
	Principal int64
}

func (l Loan) Owner() string {
	return l.CreatedBy
}
