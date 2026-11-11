package jobs

import "sync"

func fanOut(batches []int64) int64 {
	results := make(chan int64, len(batches))
	var group sync.WaitGroup
	for _, batch := range batches {
		group.Add(1)
		go func(weight int64) {
			defer group.Done()
			results <- weight * 2
		}(batch)
	}
	group.Wait()
	close(results)
	var total int64
	for item := range results {
		total += item
	}
	return total
}
