package udprelay

import (
	"context"
	"sync"
	"time"
)

// Квота TURN считается на username, поэтому залп Allocate от всех стримов сразу упирается
// в неё плотнее, чем очередь: шлюз раздаёт слоты по одному на allocPaceInterval.
const allocPaceInterval = 200 * time.Millisecond

type allocPacer struct {
	mu   sync.Mutex
	next time.Time
	step time.Duration
}

func newAllocPacer(step time.Duration) *allocPacer {
	return &allocPacer{step: step}
}

// wait возвращает false, только если ctx отменён - слот всё равно занят и не переиспользуется.
func (p *allocPacer) wait(ctx context.Context) bool {
	if p == nil {
		return ctx.Err() == nil
	}
	wait := time.Until(p.slot())
	if wait <= 0 {
		return ctx.Err() == nil
	}
	t := time.NewTimer(wait)
	defer t.Stop()
	select {
	case <-t.C:
		return true
	case <-ctx.Done():
		return false
	}
}

func (p *allocPacer) slot() time.Time {
	p.mu.Lock()
	defer p.mu.Unlock()
	now := time.Now()
	if p.next.Before(now) {
		p.next = now
	}
	slot := p.next
	p.next = slot.Add(p.step)
	return slot
}
