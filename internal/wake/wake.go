// Package wake раздаёт сигнал "устройство только что проснулось".
//
// Suspend останавливает не только код, но и весь сетевой стек: TURN-аллокация
// живёт 10 минут и после часа сна мертва, а её смерть ловится только по двум
// подряд провалам ChannelBind refresh - до ~10 минут молчащего туннеля. Сигнал
// даёт стримам повод пересоздать аллокацию сразу и не выжидать backoff.
//
// Источников два: собственный детектор ([Notifier.Watch]) и явный пинок хоста,
// который знает про пробуждение раньше (SCREEN_ON, выход приложения на передний
// план).
package wake

import (
	"context"
	"sync"
	"time"
)

// Notifier - широковещательный сигнал: слушателей произвольное число, все видят
// одно срабатывание.
type Notifier struct {
	mu sync.Mutex
	ch chan struct{}
}

func New() *Notifier {
	return &Notifier{ch: make(chan struct{})}
}

// Chan закрывается на ближайшем [Notifier.Fire]. Канал одноразовый: после
// срабатывания брать заново. Нулевой указатель отдаёт nil - чтение из него
// блокируется навсегда, и вызывающему не нужен отдельный случай "сигнала нет".
func (n *Notifier) Chan() <-chan struct{} {
	if n == nil {
		return nil
	}
	n.mu.Lock()
	defer n.mu.Unlock()
	n.initLocked()
	return n.ch
}

func (n *Notifier) Fire() {
	if n == nil {
		return
	}
	n.mu.Lock()
	defer n.mu.Unlock()
	n.initLocked()
	close(n.ch)
	n.ch = make(chan struct{})
}

// Нулевая структура (не указатель) рабочая: New нужен только чтобы канал
// существовал до первого обращения.
func (n *Notifier) initLocked() {
	if n.ch == nil {
		n.ch = make(chan struct{})
	}
}

// Watch блокирует до отмены ctx, сравнивая на каждом тике прирост стенных часов
// с монотонным. Разрыв больше threshold - устройство спало: onGap (может быть
// nil) получает его длительность, слушатели - сигнал.
//
// Побочно ловит и скачки стенных часов (NTP) - срабатывание дешёвое, отдельно
// их различать не за чем.
func (n *Notifier) Watch(ctx context.Context, tick, threshold time.Duration, onGap func(time.Duration)) {
	t := time.NewTicker(tick)
	defer t.Stop()

	last := time.Now()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			now := time.Now()
			// Round(0) снимает монотонную компоненту: во время suspend она стоит,
			// а стенные часы идут - их расхождение и есть длительность сна.
			gap := now.Round(0).Sub(last.Round(0)) - now.Sub(last)
			last = now
			if gap < threshold {
				continue
			}
			if onGap != nil {
				onGap(gap)
			}
			n.Fire()
		}
	}
}
