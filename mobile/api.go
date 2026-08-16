// Package mobile - фасад ядра для gomobile bind (Android/iOS).
//
// Экспортируются только примитивные типы, структуры этого пакета и интерфейсы,
// реализуемые хостом - ограничение gomobile. Логика сессии живёт в
// internal/session и общая с cmd/client; конфиг разбирает internal/config тем же
// путём, что и CLI. Здесь остаются разбор входа, единственный синглтон и
// конвертация типов.
//
// Порядок работы хоста:
//
//  1. SetEventSink / SetProtect - до первого Start;
//  2. Start(configJSON) - валидация синхронна, ошибка возвращается сразу;
//  3. состояние приходит в EventSink, метрики читаются GetState;
//  4. Stop() - блокирует до фактической остановки сессии.
package mobile

import (
	"context"
	"errors"
	"fmt"
	"math"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/samosvalishe/free-turn-proxy/internal/config"
	"github.com/samosvalishe/free-turn-proxy/internal/provider/vk"
	"github.com/samosvalishe/free-turn-proxy/internal/session"
	"github.com/samosvalishe/free-turn-proxy/internal/statedir"
	"github.com/samosvalishe/free-turn-proxy/internal/sub"
	"github.com/samosvalishe/free-turn-proxy/internal/tunnel"
	"github.com/samosvalishe/free-turn-proxy/internal/tunnel/awg"
)

// Состояния подключения (дублируют session.Phase*).
const (
	StateIdle       = "idle"
	StateConnecting = "connecting"
	StateConnected  = "connected"
	StateError      = "error"
	// Пользователь решает капчу вручную (watchdog не считает это зависанием).
	StateCaptcha = "captcha"
)

const (
	// Лимит ожидания первого стрима для UI.
	connectTimeout = 15 * time.Second
	// Лимит ожидания во избежание конфликта портов при перезапуске.
	stopTimeout = 5 * time.Second
	// Отдельный лимит на сворачивание туннеля: устройство закрывается уже после
	// того, как сессия отпустила свою половину пары.
	tunnelCloseTimeout = 3 * time.Second
)

// ErrTunnelRequiresStartTunnel - попытка вызвать Start с tunnel.mode wg/awg.
// Хост должен вызвать StartTunnel, передав tun-дескриптор платформы.
var ErrTunnelRequiresStartTunnel = errors.New("tunnel mode requires StartTunnel with a platform tun fd")

// Подставляется при сборке.
var version = "dev"

func Version() string { return version }

// live - запущенная сессия с отменой и туннелем.
type live struct {
	sess   *session.Session
	cancel context.CancelFunc
	done   chan struct{}
	total  int
	tunnel *tunnelParts
}

// final - статус после завершения сессии.
type final struct {
	state  string
	errMsg string
	total  int
}

var (
	// mu сериализует Start/Stop; чтение идет мимо.
	mu      sync.Mutex
	current atomic.Pointer[live]
	// finishing - сессия, которую снял с current не Stop, а её собственная
	// горутина: пока та не досворачивала туннель, останавливаться нельзя.
	finishing atomic.Pointer[live]
	lastStop  atomic.Pointer[final]
)

// Snapshot - консистентный срез состояния сессии для тика UI.
type Snapshot struct {
	State   string // idle | connecting | connected | captcha | error
	Streams int    // подключённых TURN-потоков прямо сейчас
	Total   int    // целевое число потоков
	ErrMsg  string // непустой при State == error
	TxTotal int64  // всего отправлено байт
	RxTotal int64  // всего получено байт
	TxRate  int64  // текущая скорость отправки, байт/с
	RxRate  int64  // текущая скорость получения, байт/с
}

func GetState() *Snapshot {
	if l := current.Load(); l != nil {
		s := l.sess.Snapshot()
		return &Snapshot{
			State:   string(s.Phase),
			Streams: s.Streams,
			Total:   s.Total,
			ErrMsg:  s.Err,
			TxTotal: clampToInt64(s.TxTotal),
			RxTotal: clampToInt64(s.RxTotal),
			TxRate:  s.TxRate,
			RxRate:  s.RxRate,
		}
	}
	if f := lastStop.Load(); f != nil {
		return &Snapshot{State: f.state, ErrMsg: f.errMsg, Total: f.total}
	}
	return &Snapshot{State: StateIdle}
}

// clampToInt64 насыщает uint64 до int64: gomobile экспортирует только int64,
// а счётчики байт - uint64.
func clampToInt64(u uint64) int64 {
	if u > math.MaxInt64 {
		return math.MaxInt64
	}
	return int64(u)
}

// SetStateDir задаёт каталог состояния между запусками (поколение VK-персоны,
// кэш TURN-реквизитов). Вызывать до Start.
//
// Без него на Android состояние не сохраняется вообще: кандидаты по умолчанию -
// каталог бинаря, UserConfigDir и TempDir - из app-uid не пишутся. Каталог
// должен быть приватным для приложения и вне облачного бэкапа (noBackupFilesDir).
func SetStateDir(path string) { statedir.SetDir(path) }

// Хост строит из него стартовое состояние формы.
func DefaultConfigJSON() string { return config.DefaultClientJSON() }

// Для live-валидации формы без запуска.
func ValidateConfig(configJSON string) string {
	if _, err := config.ParseClientJSON([]byte(configJSON), ""); err != nil {
		return err.Error()
	}
	return ""
}

// Для экрана "какая команда работает" (гарантирует совпадение с ядром).
func ConfigToArgs(configJSON string) (string, error) {
	c, err := config.ParseClientJSON([]byte(configJSON), "")
	if err != nil {
		return "", err
	}
	return strings.Join(config.ClientArgs(c), " "), nil
}

// Запуск в режиме прокси (для tunnel.mode wg/awg нужен StartTunnel).
func Start(configJSON string) error {
	mu.Lock()
	defer mu.Unlock()
	if current.Load() != nil {
		return errors.New("already running")
	}
	return startLocked(configJSON, 0, false)
}

// Пересоздание сессии с новым конфигом (при смене сети). tunFD - свежая копия
// дескриптора: прежнюю ядро закрыло вместе с устройством. 0 - режим прокси, без
// туннеля; владение дескриптором ядро берёт только при tunFD > 0.
func Restart(configJSON string, tunFD int) error {
	if tunFD < 0 {
		return fmt.Errorf("bad tun fd %d", tunFD)
	}
	mu.Lock()
	defer mu.Unlock()
	stopLocked()
	return startLocked(configJSON, tunFD, tunFD > 0)
}

func Stop() {
	mu.Lock()
	defer mu.Unlock()
	stopLocked()
}

// Wake - устройство проснулось (SCREEN_ON, возврат приложения на передний план).
// Стримы бросают backoff и пересоздают TURN-аллокации, не дожидаясь двух
// провалов ChannelBind refresh - до ~10 минут молчащего туннеля. Без сессии
// ничего не делает; собственный детектор сна в ядре работает независимо.
func Wake() {
	if l := current.Load(); l != nil {
		l.sess.Wake()
	}
}

func stopLocked() {
	l := current.Swap(nil)
	if l == nil {
		// Сессия кончилась сама, её туннель сворачивает та же горутина - и пока она
		// не отпустила tun-дескриптор, возврат отсюда означал бы для хоста "VPN
		// выключен" при живом интерфейсе, а для Restart - второе устройство поверх.
		if prev := finishing.Swap(nil); prev != nil {
			waitDone(prev.done, stopTimeout)
		}
		lastStop.Store(&final{state: StateIdle})
		return
	}
	finishing.CompareAndSwap(l, nil)
	l.cancel()
	waitDone(l.done, stopTimeout)
	// Синхронно: пока устройство не отпустило tun-дескриптор, платформа не снимет
	// интерфейс - для хоста это "VPN не выключился".
	closeTunnel(l.tunnel)
	// Store, а не CAS: явная остановка - это idle, чем бы ни кончилась сессия.
	lastStop.Store(&final{state: StateIdle})
}

// Потолок по времени: backend.Down() зависал в upstream amneziawg-go.
func closeTunnel(t *tunnelParts) {
	if t == nil {
		return
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		t.close()
	}()
	waitDone(done, tunnelCloseTimeout)
}

func waitDone(done <-chan struct{}, limit time.Duration) {
	select {
	case <-done:
	case <-time.After(limit):
	}
}

func startLocked(configJSON string, tunFD int, withTunnel bool) error {
	// До Up дескриптор наш: ранний выход (и конфиг без туннеля) иначе оставит
	// копию хоста висеть до конца процесса.
	ownFD := withTunnel
	defer func() {
		if ownFD {
			awg.CloseTUNFD(tunFD)
		}
	}()

	raw := []byte(configJSON)

	// Подписка отдаёт peer, без которого конфиг не проходит валидацию, поэтому
	// тянем её до разбора и накладываем URI ноды поверх.
	overlayURI := ""
	if subURL := config.PeekSubURLJSON(raw); subURL != "" {
		s, err := sub.Fetch(context.Background(), subURL)
		if err != nil {
			return fmt.Errorf("failed to fetch subscription: %w", err)
		}
		if len(s.Nodes) == 0 || s.Nodes[0].URI == nil {
			return errors.New("no nodes found in subscription")
		}
		overlayURI = s.Nodes[0].URI.String()
	}

	cfg, err := config.ParseClientJSON(raw, overlayURI)
	if err != nil {
		return err
	}
	// ID клиента постоянный и живет в приложении.
	if cfg.ClientID == "" {
		return errors.New("clientId is required")
	}
	if cfg.VK.ManualCaptcha && currentSink() == nil {
		return errors.New("manual captcha requires event sink")
	}
	if cfg.Tunnel.Enabled() && !withTunnel {
		return fmt.Errorf("%w (mode=%s)", ErrTunnelRequiresStartTunnel, cfg.Tunnel.Mode)
	}

	logger := &sinkLogger{debug: cfg.Log.Debug, buf: sharedLogBuf}

	// Туннель требует in-memory PacketConn до старта сессии.
	var parts *tunnelParts
	var tunCfg *tunnel.Config
	if cfg.Tunnel.Enabled() {
		parts, tunCfg, err = buildTunnel(cfg, logger)
		if err != nil {
			return err
		}
	}

	// Держит watchdog, пока пользователь решает капчу.
	var captchaActive atomic.Bool
	var solver vk.ManualSolverFunc
	if currentSink() != nil {
		solver = vk.ProxyManualSolver(
			func(url string) { captchaActive.Store(true); emitCaptcha(url) },
			func() { captchaActive.Store(false); emitCaptcha("") },
		)
	}

	deps := session.Deps{
		Logger:        logger,
		Observer:      observer{},
		Solver:        solver,
		CaptchaActive: captchaActive.Load,
		Options: session.Options{
			ConnectTimeout: connectTimeout,
			Traffic:        true,
		},
	}
	if parts != nil {
		deps.LocalPipe = parts.relaySide
	}

	sess, err := session.New(cfg, deps)
	if err != nil {
		parts.close()
		return err
	}

	// Handshake повторяется в фоне, ждать готовности не нужно.
	if parts != nil {
		ownFD = false // Up забирает владение, включая свою неудачу
		if err := parts.backend.Up(tunCfg, tunFD); err != nil {
			parts.close()
			return err
		}
	}

	ClearLogs()
	ctx, cancel := context.WithCancel(context.Background())
	l := &live{
		sess:   sess,
		cancel: cancel,
		done:   make(chan struct{}),
		total:  sess.Snapshot().Total,
		tunnel: parts,
	}
	current.Store(l)
	finishing.Store(nil)
	lastStop.Store(nil)

	go func() {
		defer close(l.done)
		runErr := sess.Run(ctx)
		cancel()

		// Публикуемся до CAS: Stop, заставший current уже пустым, обязан найти нас
		// здесь - иначе вернётся, пока туннель ещё сворачивается.
		finishing.Store(l)
		// Если Stop перехватил сессию, финальный статус и туннель - его.
		if !current.CompareAndSwap(l, nil) {
			finishing.CompareAndSwap(l, nil)
			return
		}
		// Сессия кончилась сама (ошибка, таймаут подключения): без этого устройство
		// и tun-дескриптор пережили бы её, а Restart поднял бы поверх второе.
		closeTunnel(l.tunnel)
		if runErr != nil {
			lastStop.Store(&final{state: StateError, errMsg: runErr.Error(), total: l.total})
			return
		}
		lastStop.Store(&final{state: StateIdle})
	}()

	return nil
}
