package ledger

type Poster interface {
	Post(amount int64) error
	Total() int64
}

type cashPoster struct {
	posted int64
}

func (c *cashPoster) Post(amount int64) error {
	c.posted += amount
	return nil
}

func (c *cashPoster) Total() int64 {
	return c.posted
}
