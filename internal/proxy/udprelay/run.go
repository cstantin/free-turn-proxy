// Package udprelay реализует ретрансляцию UDP-трафика через параллельные DTLS/TURN сессии.
package udprelay

import (
	"context"
	"errors"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/samosvalishe/free-turn-proxy/internal/logx"
	"github.com/samosvalishe/free-turn-proxy/internal/proxy/common"
	"github.com/samosvalishe/free-turn-proxy/internal/stats"
	"github.com/samosvalishe/free-turn-proxy/internal/transport/dtlsdial"
	"github.com/samosvalishe/free-turn-proxy/internal/wake"
)

type GetCredsFunc = common.GetCredsFunc

// AuthHandler определяет интерфейс взаимодействия с провайдером при ошибках авторизации.
type AuthHandler interface {
	IsAuthError(err error) bool
	HandleAuthError(streamID int) bool
	ResetErrors(streamID int)
	BackoffUntilUnix() int64
}

// Params содержит конфигурацию подключения к TURN и параметры обфускации.
type Params struct {
	Host         string
	Port         string
	TransportUDP bool
	Profile      string
	ObfKey       []byte
	ObfTiming    time.Duration
	GetCreds     GetCredsFunc
	ClientID     string
	TrafficStats *stats.Stats
}

const streamStartBarrier = 20 * time.Second

// ErrFatal возвращается при фатальных ошибках провайдера, требующих остановки клиента.
var ErrFatal = errors.New("udprelay: fatal error")

type Deps struct {
	DTLSDialer       *dtlsdial.Dialer
	Auth             AuthHandler
	Log              logx.Logger
	ActiveLocalPeer  *atomic.Value
	ConnectedStreams *atomic.Int32
	OnTURNServer     func(ip net.IP)
	Wake             *wake.Notifier
	fatalCh          chan error
}

func (d *Deps) log() logx.Logger {
	if d.Log == nil {
		return logx.Nop()
	}
	return d.Log
}

func (d *Deps) woke() <-chan struct{} { return d.Wake.Chan() }

// Run запускает прием входящего UDP-трафика и распределяет его по пулу пар DTLSLoop/TURNLoop.
func Run(ctx context.Context, dtlsDialer *dtlsdial.Dialer, auth AuthHandler, logger logx.Logger, connectedStreams *atomic.Int32, onTURNServer func(net.IP), waker *wake.Notifier, params *Params, peer *net.UDPAddr, listenConn net.PacketConn, numStreams int) error {
	context.AfterFunc(ctx, func() {
		if closeErr := listenConn.Close(); closeErr != nil {
			logger.Errorf("udprelay: close local connection: %s", closeErr)
		}
	})

	if numStreams <= 0 {
		numStreams = 1
	}

	fatalCh := make(chan error, 1)
	var activeLocalPeer atomic.Value
	deps := &Deps{
		DTLSDialer:       dtlsDialer,
		Auth:             auth,
		Log:              logger,
		ActiveLocalPeer:  &activeLocalPeer,
		ConnectedStreams: connectedStreams,
		OnTURNServer:     onTURNServer,
		Wake:             waker,
		fatalCh:          fatalCh,
	}

	runCtx, runCancel := context.WithCancel(ctx)
	defer runCancel()

	inboundChan := make(chan *Packet, inboundQueueCap)
	wg := sync.WaitGroup{}
	wg.Go(func() {
		runListener(runCtx, listenConn, &activeLocalPeer, inboundChan)
	})
	t := time.Tick(200 * time.Millisecond)

	// Стрим 1 стартует первым для прогрева кэша учетных данных.
	okchan := make(chan struct{}, 1)
	{
		cchan := make(chan net.PacketConn)
		wg.Go(func() {
			DTLSLoop(runCtx, deps, params, peer, listenConn, inboundChan, cchan, okchan, 1)
		})
		wg.Go(func() {
			TURNLoop(runCtx, deps, params, peer, cchan, t, 1)
		})
	}

	select {
	case <-okchan:
	case <-runCtx.Done():
	case <-time.After(streamStartBarrier):
	}

	for i := 1; i < numStreams; i++ {
		cchan := make(chan net.PacketConn)
		streamID := i + 1
		wg.Go(func() {
			DTLSLoop(runCtx, deps, params, peer, listenConn, inboundChan, cchan, nil, streamID)
		})
		wg.Go(func() {
			TURNLoop(runCtx, deps, params, peer, cchan, t, streamID)
		})
	}

	var fatalErr atomic.Pointer[error]
	watcherDone := make(chan struct{})
	go func() {
		defer close(watcherDone)
		select {
		case err := <-fatalCh:
			fatalErr.Store(&err)
			runCancel()
		case <-runCtx.Done():
		}
	}()

	wg.Wait()
	runCancel()
	<-watcherDone
	if p := fatalErr.Load(); p != nil {
		return *p
	}
	return nil
}
