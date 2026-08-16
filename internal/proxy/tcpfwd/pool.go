// Package tcpfwd реализует VLESS-режим: пересылка TCP через пул TURN-туннелированных
// smux-сессий. Каждое принятое TCP-соединение открывается как smux-поток
// (round-robin по сессиям) или, с bond, распределяется по всем активным сессиям.
//
// SessionPool/PooledSession экспортированы, чтобы bond-клиент (internal/proxy/bondclient)
// мог распределять одно TCP-соединение по нескольким сессиям.
package tcpfwd

import (
	"sync"
	"sync/atomic"

	"github.com/xtaci/smux"
)

// PooledSession - одна TURN+DTLS+KCP+smux сессия. Поля экспортированы для
// per-lane трафика в bondclient; атомики изменять только через их методы.
type PooledSession struct {
	ID          int
	Sess        *smux.Session
	Active      atomic.Int32
	Opened      atomic.Uint64
	Closed      atomic.Uint64
	ToSession   atomic.Uint64
	FromSession atomic.Uint64
}

// SessionPool - конкурентно-безопасный round-robin пул активных smux-сессий.
type SessionPool struct {
	mu          sync.RWMutex
	sessions    []*PooledSession
	counter     atomic.Uint64
	connCounter atomic.Uint64

	// active - зеркало числа живых сессий для watchdog/UI. nil, если не просили.
	active *atomic.Int32

	readyOnce sync.Once
	ready     chan struct{}
}

// publishActive обновляет внешнее зеркало. Вызывать под p.mu.
func (p *SessionPool) publishActive() {
	if p.active != nil {
		p.active.Store(int32(len(p.sessions))) //nolint:gosec // сессий десятки, int32 не переполнить
	}
}

func (p *SessionPool) Ready() <-chan struct{} {
	p.mu.Lock()
	if p.ready == nil {
		p.ready = make(chan struct{})
	}
	ch := p.ready
	p.mu.Unlock()
	return ch
}

func (p *SessionPool) Add(id int, s *smux.Session) *PooledSession {
	ps := &PooledSession{ID: id, Sess: s}
	p.mu.Lock()
	p.sessions = append(p.sessions, ps)
	p.publishActive()
	if p.ready == nil {
		p.ready = make(chan struct{})
	}
	ready := p.ready
	p.mu.Unlock()
	p.readyOnce.Do(func() { close(ready) })
	return ps
}

// Remove no-op если ps не найден.
func (p *SessionPool) Remove(ps *PooledSession) {
	p.mu.Lock()
	for i, sess := range p.sessions {
		if sess == ps {
			p.sessions = append(p.sessions[:i], p.sessions[i+1:]...)
			break
		}
	}
	p.publishActive()
	p.mu.Unlock()
}

// Pick - nil если пул пуст.
func (p *SessionPool) Pick() *PooledSession {
	p.mu.RLock()
	defer p.mu.RUnlock()
	n := len(p.sessions)
	if n == 0 {
		return nil
	}
	idx := (p.counter.Add(1) - 1) % uint64(n)
	return p.sessions[idx]
}

func (p *SessionPool) NextConnID() uint64 {
	return p.connCounter.Add(1)
}

// Snapshot - копия незакрытых сессий.
func (p *SessionPool) Snapshot() []*PooledSession {
	p.mu.RLock()
	defer p.mu.RUnlock()
	out := make([]*PooledSession, 0, len(p.sessions))
	for _, ps := range p.sessions {
		if !ps.Sess.IsClosed() {
			out = append(out, ps)
		}
	}
	return out
}

// Count включает только что закрытые сессии; для live-only используй Snapshot.
func (p *SessionPool) Count() int {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return len(p.sessions)
}
