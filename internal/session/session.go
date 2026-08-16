// Package session управляет жизненным циклом клиентской сессии и релея трафика.
package session

import (
	"context"
	"errors"
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/samosvalishe/free-turn-proxy/internal/client/dnsdial"
	"github.com/samosvalishe/free-turn-proxy/internal/config"
	"github.com/samosvalishe/free-turn-proxy/internal/logx"
	"github.com/samosvalishe/free-turn-proxy/internal/provider"
	"github.com/samosvalishe/free-turn-proxy/internal/provider/vk"
	"github.com/samosvalishe/free-turn-proxy/internal/proxy/udprelay"
	"github.com/samosvalishe/free-turn-proxy/internal/routemgr"
	"github.com/samosvalishe/free-turn-proxy/internal/stats"
	"github.com/samosvalishe/free-turn-proxy/internal/transport/dtlsdial"
	"github.com/samosvalishe/free-turn-proxy/internal/wake"
)

// Phase - текущая стадия подключения сессии.
type Phase string

const (
	PhaseIdle       Phase = "idle"
	PhaseConnecting Phase = "connecting"
	PhaseConnected  Phase = "connected"
	// PhaseCaptcha - ожидание ручного ввода captcha пользователем.
	PhaseCaptcha Phase = "captcha"
	PhaseError   Phase = "error"
)

var (
	ErrAlreadyRun     = errors.New("session: already run")
	ErrConnectTimeout = errors.New("session: connect timeout: no stream connected within the deadline")
)

const (
	defaultStatusInterval       = 500 * time.Millisecond
	defaultRateInterval         = time.Second
	defaultUDPHandshakeTimeout  = 20 * time.Second
	defaultHandshakeConcurrency = 3

	wakeTick      = 5 * time.Second
	wakeThreshold = 60 * time.Second
)

type Options struct {
	ConnectTimeout time.Duration

	StatusInterval       time.Duration
	RateInterval         time.Duration
	UDPHandshakeTimeout  time.Duration
	HandshakeConcurrency int

	Traffic bool
}

func (o Options) withDefaults() Options {
	if o.StatusInterval <= 0 {
		o.StatusInterval = defaultStatusInterval
	}
	if o.RateInterval <= 0 {
		o.RateInterval = defaultRateInterval
	}
	if o.UDPHandshakeTimeout <= 0 {
		o.UDPHandshakeTimeout = defaultUDPHandshakeTimeout
	}
	if o.HandshakeConcurrency <= 0 {
		o.HandshakeConcurrency = defaultHandshakeConcurrency
	}
	return o
}

type Deps struct {
	Logger        logx.Logger
	Observer      Observer
	Solver        vk.ManualSolverFunc
	CaptchaActive func() bool
	// LocalPipe подменяет локальный UDP-сокет прямым каналом в памяти.
	LocalPipe net.PacketConn
	Options   Options
}

// Snapshot - моментальный снимок состояния сессии для UI.
type Snapshot struct {
	Phase   Phase
	Streams int
	Total   int
	Err     string
	TxTotal uint64
	RxTotal uint64
	TxRate  int64
	RxRate  int64
}

type statusInfo struct {
	phase   Phase
	streams int
	total   int
	err     string
}

// Session инкапсулирует состояние и управление клиентской сессией.
type Session struct {
	cfg     *config.Client
	deps    Deps
	opts    Options
	total   int
	traffic *traffic

	connected atomic.Int32
	status    atomic.Pointer[statusInfo]
	started   atomic.Bool
	wake      *wake.Notifier
}

func New(cfg *config.Client, deps Deps) (*Session, error) {
	if cfg == nil {
		return nil, errors.New("session: nil config")
	}
	if deps.Logger == nil {
		deps.Logger = logx.Nop()
	}

	total := cfg.TURN.N * max(len(cfg.VK.Links), 1)

	s := &Session{
		cfg:   cfg,
		deps:  deps,
		opts:  deps.Options.withDefaults(),
		total: total,
		wake:  wake.New(),
	}
	if s.opts.Traffic {
		s.traffic = newTraffic()
	}
	s.status.Store(&statusInfo{phase: PhaseConnecting, total: total})
	return s, nil
}

// Run запускает сессию и блокирует вызывающую горутину до завершения или ошибки.
func (s *Session) Run(ctx context.Context) (err error) {
	if !s.started.CompareAndSwap(false, true) {
		return ErrAlreadyRun
	}
	s.publish(&statusInfo{phase: PhaseConnecting, total: s.total}, true)
	defer func() {
		if err != nil {
			s.setStatus(PhaseError, 0, err.Error())
			return
		}
		s.setStatus(PhaseIdle, 0, "")
	}()

	log := s.deps.Logger
	dnsdial.SetLogger(log)
	if s.cfg.DNS.Servers != nil {
		dnsdial.SetUDPDNSServers(s.cfg.DNS.Servers)
		log.Infof("[DNS] using custom UDP servers: %v", s.cfg.DNS.Servers)
	}
	appDialer := dnsdial.AppDialer(s.cfg.DNS.Mode)
	dnsdial.InstallGlobalResolver(s.cfg.DNS.Mode)

	prov, err := buildProvider(s.cfg, appDialer, &s.connected, s.deps.Solver, log, s.total)
	if err != nil {
		return fmt.Errorf("provider init: %w", err)
	}
	log.Infof("provider=%s", prov.Name())
	if s.cfg.Obf.Enabled() {
		log.Infof("OBF profile=%s: peer server must use matching -obf-profile and -obf-key", s.cfg.Obf.Profile)
	}

	peer, err := net.ResolveUDPAddr("udp", s.cfg.Proxy.Peer)
	if err != nil {
		return fmt.Errorf("resolve peer addr: %w", err)
	}

	runCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	var bg sync.WaitGroup
	if s.traffic != nil {
		bg.Add(1)
		go func() {
			defer bg.Done()
			s.traffic.rateMeter(runCtx, s.opts.RateInterval)
		}()
	}

	bg.Add(1)
	go func() {
		defer bg.Done()
		s.wake.Watch(runCtx, wakeTick, wakeThreshold, func(gap time.Duration) {
			log.Warnf("device slept for %s - recycling TURN allocations", gap.Truncate(time.Second))
		})
	}()

	var watchdogErr error
	bg.Add(1)
	go func() {
		defer bg.Done()
		watchdogErr = s.watch(runCtx, cancel)
	}()

	relayErr := s.relay(runCtx, prov, peer)
	stopped := runCtx.Err() != nil
	cancel()
	bg.Wait()

	if relayErr != nil && !stopped {
		return relayErr
	}
	return watchdogErr
}

// Wake инициирует немедленное переподключение TURN-аллокаций после пробуждения.
func (s *Session) Wake() { s.wake.Fire() }

// Snapshot возвращает текущий снимок состояния сессии.
func (s *Session) Snapshot() Snapshot {
	st := s.status.Load()
	if st == nil {
		st = &statusInfo{phase: PhaseIdle}
	}
	snap := Snapshot{Phase: st.phase, Streams: st.streams, Total: st.total, Err: st.err}
	if s.traffic != nil {
		snap.TxTotal, snap.RxTotal = s.traffic.stats.Counters()
		snap.TxRate = s.traffic.txRate.Load()
		snap.RxRate = s.traffic.rxRate.Load()
	}
	return snap
}

func (s *Session) setStatus(phase Phase, streams int, errMsg string) {
	s.publish(&statusInfo{phase: phase, streams: streams, total: s.total, err: errMsg}, false)
}

func (s *Session) publish(next *statusInfo, force bool) {
	prev := s.status.Swap(next)
	if !force && prev != nil && *prev == *next {
		return
	}
	if s.deps.Observer != nil {
		s.deps.Observer.OnPhase(next.phase, next.streams, next.total, next.err)
	}
}

func (s *Session) captchaActive() bool {
	return s.deps.CaptchaActive != nil && s.deps.CaptchaActive()
}

// watch публикует стадию подключения и следит за ConnectTimeout.
func (s *Session) watch(ctx context.Context, cancel context.CancelFunc) error {
	tick := time.NewTicker(s.opts.StatusInterval)
	defer tick.Stop()

	deadline := time.Now().Add(s.opts.ConnectTimeout)
	everConnected := false

	for {
		select {
		case <-ctx.Done():
			return nil
		case <-tick.C:
			n := int(s.connected.Load())
			if n > 0 {
				everConnected = true
			}

			if s.captchaActive() {
				deadline = time.Now().Add(s.opts.ConnectTimeout)
				s.setStatus(PhaseCaptcha, n, "")
				continue
			}

			phase := PhaseConnecting
			if n > 0 {
				phase = PhaseConnected
			}
			s.setStatus(phase, n, "")

			if s.opts.ConnectTimeout > 0 && !everConnected && time.Now().After(deadline) {
				cancel()
				return fmt.Errorf("%w (timeout=%s)", ErrConnectTimeout, s.opts.ConnectTimeout)
			}
		}
	}
}

func (s *Session) relay(ctx context.Context, prov provider.Provider, peer *net.UDPAddr) error {
	log := s.deps.Logger
	getCreds := func(ctx context.Context, streamID int) (string, string, []string, error) {
		c, err := prov.GetCredentials(ctx, streamID)
		if err != nil {
			return "", "", nil, err
		}
		return c.User, c.Pass, c.ServerAddrs, nil
	}

	// host-route для IP TURN-серверов в обход VPN-туннеля.
	var routeCallback func(net.IP)
	if s.cfg.Routes && !s.cfg.Tunnel.Enabled() {
		rm, rmErr := routemgr.New(log)
		if rmErr != nil {
			log.Warnf("route manager disabled: %v", rmErr)
		} else if rm != nil {
			defer func() {
				_ = rm.Close()
			}()
			routeCallback = rm.Callback()
			log.Infof("route manager: gateway=%s", rm.Gateway())
		}
	}

	local, err := s.localConn(ctx)
	if err != nil {
		return err
	}

	dialer := &dtlsdial.Dialer{
		HandshakeTimeout: s.opts.UDPHandshakeTimeout,
		HandshakeSem:     make(chan struct{}, s.opts.HandshakeConcurrency),
	}
	params := &udprelay.Params{
		Host:         s.cfg.TURN.Host,
		Port:         s.cfg.TURN.Port,
		TransportUDP: s.cfg.TURN.TransportUDP,
		Profile:      string(s.cfg.Obf.Profile),
		ObfKey:       s.cfg.Obf.Key,
		ObfTiming:    s.cfg.Obf.Timing,
		GetCreds:     udprelay.GetCredsFunc(getCreds),
		ClientID:     s.cfg.ClientID,
		TrafficStats: s.trafficStats(),
	}
	return udprelay.Run(ctx, dialer, prov, log, &s.connected, routeCallback, s.wake, params, peer, local, s.total)
}

func (s *Session) localConn(ctx context.Context) (net.PacketConn, error) {
	if s.deps.LocalPipe != nil {
		s.deps.Logger.Infof("local peer: in-process pipe (no loopback socket)")
		return s.deps.LocalPipe, nil
	}
	conn, err := (&net.ListenConfig{}).ListenPacket(ctx, "udp", s.cfg.Proxy.Listen)
	if err != nil {
		return nil, fmt.Errorf("udprelay listen %s: %w", s.cfg.Proxy.Listen, err)
	}
	return conn, nil
}

func (s *Session) trafficStats() *stats.Stats {
	if s.traffic == nil {
		return nil
	}
	return s.traffic.stats
}
