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
	"github.com/samosvalishe/free-turn-proxy/internal/stats"
	"github.com/samosvalishe/free-turn-proxy/internal/transport/dtlsdial"
)

// AuthHandler определяет интерфейс взаимодействия с провайдером при ошибках авторизации.
type AuthHandler interface {
	IsAuthError(err error) bool
	HandleAuthError(streamID int) bool
	ResetErrors(streamID int)
	DropCredentials(streamID int)
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
	fatalCh          chan error
}

func (d *Deps) log() logx.Logger {
	if d.Log == nil {
		return logx.Nop()
	}
	return d.Log
}

// Run запускает прием входящего UDP-трафика и распределяет его по пулу пар DTLSLoop/TURNLoop.
func Run(ctx context.Context, dtlsDialer *dtlsdial.Dialer, auth AuthHandler, logger logx.Logger, connectedStreams *atomic.Int32, onTURNServer func(net.IP), params *Params, peer *net.UDPAddr, listenConn net.PacketConn, numStreams int) error {
	context.AfterFunc(ctx, func() {
		if err := listenConn.SetReadDeadline(time.Now()); err != nil {
			logger.Errorf("udprelay: set listen deadline: %s", err)
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
		fatalCh:          fatalCh,
	}

	runCtx, runCancel := context.WithCancel(ctx)
	defer runCancel()

	inboundChan := make(chan *Packet, inboundQueueCap)
	wg := sync.WaitGroup{}
	wg.Go(func() {
		runListener(runCtx, listenConn, &activeLocalPeer, inboundChan)
	})

	// Стрим 1 стартует первым для прогрева кэша учетных данных.
	okchan := make(chan struct{}, 1)
	{
		cchan := make(chan streamPair)
		wg.Go(func() {
			DTLSLoop(runCtx, deps, params, peer, listenConn, inboundChan, cchan, okchan, 1)
		})
		wg.Go(func() {
			TURNLoop(runCtx, deps, params, peer, cchan, 1)
		})
	}

	select {
	case <-okchan:
	case <-runCtx.Done():
	case <-time.After(streamStartBarrier):
	}

	for i := 1; i < numStreams; i++ {
		cchan := make(chan streamPair)
		streamID := i + 1
		wg.Go(func() {
			DTLSLoop(runCtx, deps, params, peer, listenConn, inboundChan, cchan, nil, streamID)
		})
		wg.Go(func() {
			TURNLoop(runCtx, deps, params, peer, cchan, streamID)
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
	// Сбрасываем дедлайн, чтобы listenConn можно было переиспользовать
	// в следующей итерации runRelayLoop (актуально для LocalPipe).
	if err := listenConn.SetReadDeadline(time.Time{}); err != nil {
		logger.Errorf("udprelay: clear listen deadline: %s", err)
	}
	runCancel()
	<-watcherDone
	if p := fatalErr.Load(); p != nil {
		return *p
	}
	return nil
}
