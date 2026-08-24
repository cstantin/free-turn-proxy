package udprelay

import (
	"context"
	"sync"
	"testing"
	"time"
)

// Смысл шлюза - очередь, а не пауза: N стримов обязаны разъехаться на N-1 шагов.
func TestAllocPacerSpacesConcurrentWaiters(t *testing.T) {
	t.Parallel()
	const (
		step     = 20 * time.Millisecond
		waiters  = 5
		slowdown = 3
	)
	p := newAllocPacer(step)

	start := time.Now()
	var wg sync.WaitGroup
	elapsed := make([]time.Duration, waiters)
	for i := range waiters {
		wg.Go(func() {
			if !p.wait(context.Background()) {
				t.Errorf("waiter %d: wait returned false", i)
				return
			}
			elapsed[i] = time.Since(start)
		})
	}
	wg.Wait()

	var last time.Duration
	for _, e := range elapsed {
		last = max(last, e)
	}
	if want := (waiters - 1) * step; last < want {
		t.Fatalf("last waiter passed after %v, want at least %v", last, want)
	}
	if limit := slowdown * waiters * step; last > limit {
		t.Fatalf("last waiter passed after %v, want under %v", last, limit)
	}
}

// Первый в очереди не платит ничего: рецикл одинокого стрима не должен ждать шаг.
func TestAllocPacerFirstSlotIsFree(t *testing.T) {
	t.Parallel()
	p := newAllocPacer(time.Second)

	start := time.Now()
	if !p.wait(context.Background()) {
		t.Fatal("wait returned false")
	}
	if elapsed := time.Since(start); elapsed > 100*time.Millisecond {
		t.Fatalf("first wait took %v, want immediate", elapsed)
	}
}

func TestAllocPacerWaitReturnsFalseOnCancel(t *testing.T) {
	t.Parallel()
	p := newAllocPacer(time.Hour)
	p.slot() // занять первый слот, следующий уедет на час

	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		time.Sleep(10 * time.Millisecond)
		cancel()
	}()
	if p.wait(ctx) {
		t.Fatal("wait returned true on cancelled context")
	}
}

// Nil-приёмник допустим: Deps собирают и в обход Run.
func TestAllocPacerNilIsPassthrough(t *testing.T) {
	t.Parallel()
	var p *allocPacer
	if !p.wait(context.Background()) {
		t.Fatal("nil pacer must pass through")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if p.wait(ctx) {
		t.Fatal("nil pacer must respect cancelled context")
	}
}
