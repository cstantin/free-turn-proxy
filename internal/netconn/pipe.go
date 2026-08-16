package netconn

import (
	"context"
	"io"
	"net"
	"sync"
	"time"
)

// BiCopy выполняет двунаправленное копирование между c1 и c2 с закрытием по первому завершению.
func BiCopy(ctx context.Context, c1, c2 net.Conn, errf func(format string, v ...any)) (int64, int64) {
	ctx2, cancel := context.WithCancel(ctx)
	context.AfterFunc(ctx2, func() {
		now := time.Now()
		if err := c1.SetDeadline(now); err != nil && errf != nil {
			errf("BiCopy: c1 SetDeadline: %v", err)
		}
		if err := c2.SetDeadline(now); err != nil && errf != nil {
			errf("BiCopy: c2 SetDeadline: %v", err)
		}
	})

	var wg sync.WaitGroup
	var c1FromC2, c2FromC1 int64
	wg.Go(func() {
		defer cancel()
		n, err := io.Copy(c1, c2)
		c1FromC2 = n
		if err != nil && errf != nil {
			errf("BiCopy: c1<-c2: %v", err)
		}
	})
	wg.Go(func() {
		defer cancel()
		n, err := io.Copy(c2, c1)
		c2FromC1 = n
		if err != nil && errf != nil {
			errf("BiCopy: c2<-c1: %v", err)
		}
	})
	wg.Wait()

	if err := c1.SetDeadline(time.Time{}); err != nil && errf != nil {
		errf("BiCopy: c1 clear deadline: %v", err)
	}
	if err := c2.SetDeadline(time.Time{}); err != nil && errf != nil {
		errf("BiCopy: c2 clear deadline: %v", err)
	}
	return c1FromC2, c2FromC1
}
