package udprelay

import (
	"context"
	"errors"
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/cbeuw/connutil"
	"github.com/samosvalishe/free-turn-proxy/internal/clientsdb"
	"github.com/samosvalishe/free-turn-proxy/internal/provider"
	"github.com/samosvalishe/free-turn-proxy/internal/randx"
	"github.com/samosvalishe/free-turn-proxy/internal/wire"
	"github.com/samosvalishe/free-turn-proxy/internal/wire/shape"
)

// DTLSLoop поддерживает и перезапускает DTLS-соединение для указанного streamID.
func DTLSLoop(ctx context.Context, deps *Deps, params *Params, peer *net.UDPAddr, listenConn net.PacketConn, inboundChan <-chan *Packet, connchan chan<- net.PacketConn, okchan chan<- struct{}, streamID int) {
	for {
		select {
		case <-ctx.Done():
			return
		default:
			err := oneDTLS(ctx, deps, params, peer, listenConn, inboundChan, connchan, okchan, streamID)
			if err != nil && time.Now().Unix() < deps.Auth.BackoffUntilUnix() && errors.Is(err, context.DeadlineExceeded) {
				select {
				case <-ctx.Done():
					return
				case <-time.After(time.Duration(1+randx.Intn(2)) * time.Second):
				}
				continue
			}
			if err != nil {
				select {
				case <-ctx.Done():
					return
				case <-time.After(time.Duration(10+randx.Intn(20)) * time.Second):
				}
			}
		}
	}
}

// TURNLoop управляет жизненным циклом одной TURN-аллокации.
func TURNLoop(ctx context.Context, deps *Deps, params *Params, peer *net.UDPAddr, connchan <-chan net.PacketConn, streamID int) {
	for {
		select {
		case <-ctx.Done():
			return
		case conn2 := <-connchan:
			// Джиттер разводит Allocate соседних стримов во времени.
			select {
			case <-time.After(time.Duration(randx.Intn(400)+100) * time.Millisecond):
			case <-ctx.Done():
				return
			}
			c := make(chan error, 1)
			go oneTURN(ctx, deps, params, peer, conn2, streamID, c)

			var err error
			select {
			case err = <-c:
			case <-ctx.Done():
				return
			}
			if err != nil {
				if errors.Is(err, provider.ErrFatalNoStreams) {
					deps.log().Errorf("[STREAM %d] Fatal provider error. Shutting down application.", streamID)
					select {
					case deps.fatalCh <- fmt.Errorf("%w: %w", ErrFatal, err):
					default:
					}
					return
				}
				if errors.Is(err, provider.ErrBackoffActive) {
					lockoutEnd := deps.Auth.BackoffUntilUnix()
					var sleepDuration time.Duration
					if lockoutEnd > 0 {
						sleepDuration = time.Until(time.Unix(lockoutEnd, 0))
						if sleepDuration < 0 {
							sleepDuration = 5 * time.Second
						}
					} else {
						sleepDuration = 60 * time.Second
						deps.log().Warnf("[STREAM %d] Backing off for 60 seconds (provider requests wait)", streamID)
					}
					select {
					case <-ctx.Done():
						return
					case <-time.After(sleepDuration):
					}
				} else {
					deps.log().Errorf("[STREAM %d] %s", streamID, err)
					select {
					case <-ctx.Done():
						return
					case <-time.After(2 * time.Second):
					}
				}
			}
		}
	}
}

func oneDTLS(ctx context.Context, deps *Deps, params *Params, peer *net.UDPAddr, listenConn net.PacketConn, inboundChan <-chan *Packet, connchan chan<- net.PacketConn, okchan chan<- struct{}, streamID int) error {
	select {
	case <-time.After(time.Duration(randx.Intn(400)+100) * time.Millisecond):
	case <-ctx.Done():
		return ctx.Err()
	}

	dtlsctx, dtlscancel := context.WithCancel(ctx)
	defer dtlscancel()

	conn1, conn2 := connutil.AsyncPacketPipe()
	defer func() { _ = conn1.Close() }()
	defer func() { _ = conn2.Close() }()
	go func() {
		for {
			select {
			case <-dtlsctx.Done():
				return
			case connchan <- conn2:
			}
		}
	}()
	dtlsRaw, err1 := deps.DTLSDialer.Dial(dtlsctx, conn1, peer)
	if err1 != nil {
		return fmt.Errorf("failed to connect DTLS: %w", err1)
	}
	var dtlsConn net.Conn = dtlsRaw
	defer func() {
		_ = dtlsConn.Close()
		deps.log().Infof("[STREAM %d] Closed DTLS connection", streamID)
	}()
	deps.log().Infof("[STREAM %d] Established DTLS connection", streamID)

	if err := clientsdb.WriteClientID(dtlsConn, params.ClientID); err != nil {
		return fmt.Errorf("failed to write client ID: %w", err)
	}
	if okchan != nil {
		select {
		case okchan <- struct{}{}:
		default:
		}
	}

	forwardDone := make(chan struct{})
	go func() {
		defer close(forwardDone)
		var buf [2048]byte
		for {
			n, err := dtlsConn.Read(buf[:])
			if err != nil {
				return
			}
			addr := deps.ActiveLocalPeer.Load()
			if addr == nil {
				continue
			}
			netAddr, ok := addr.(net.Addr)
			if !ok {
				continue
			}
			_, writeErr := listenConn.WriteTo(buf[:n], netAddr)
			if writeErr != nil {
				return
			}
		}
	}()

	for {
		select {
		case <-dtlsctx.Done():
			return dtlsctx.Err()
		case <-forwardDone:
			return errors.New("DTLS connection closed by remote peer")
		case pkt := <-inboundChan:
			_, err := dtlsConn.Write(pkt.Data[:pkt.N])
			packetPool.Put(pkt)
			if err != nil {
				return fmt.Errorf("failed to forward packet to DTLS: %w", err)
			}
		}
	}
}

func oneTURN(ctx context.Context, deps *Deps, params *Params, peer *net.UDPAddr, conn2 net.PacketConn, streamID int, c chan<- error) {
	var err error
	defer func() {
		c <- err
	}()

	stream, derr := DialTURN(ctx, params.Host, params.Port, params.TransportUDP, peer, streamID, params.GetCreds)
	if derr != nil {
		if deps.Auth.IsAuthError(derr) {
			deps.Auth.HandleAuthError(streamID)
		}
		err = fmt.Errorf("connect to TURN server: %w", derr)
		return
	}
	relayConn := stream.Relay
	deps.log().Debugf("[STREAM %d] TURN server IP: %s", streamID, stream.ServerUDPAddr.IP)
	if deps.OnTURNServer != nil {
		deps.OnTURNServer(stream.ServerUDPAddr.IP)
	}

	if params.ObfTiming > 0 {
		relayConn = shape.WrapPacketConn(relayConn, params.ObfTiming)
		deps.log().Debugf("[STREAM %d] obf-timing=%s", streamID, params.ObfTiming)
	}

	deps.ConnectedStreams.Add(1)
	deps.Auth.ResetErrors(streamID)

	defer func() {
		deps.ConnectedStreams.Add(-1)
		if cerr := stream.Close(); cerr != nil {
			err = fmt.Errorf("failed to close TURN stream: %w", cerr)
		}
	}()

	deps.log().Debugf("[STREAM %d] relayed-address=%s", streamID, relayConn.LocalAddr().String())

	wg := sync.WaitGroup{}
	turnctx, turncancel := context.WithCancel(ctx)
	defer turncancel()

	// без дедлайна relayConn.ReadFrom не проснётся на отмене turnctx - wg.Wait встанет намертво
	context.AfterFunc(turnctx, func() {
		if err := relayConn.SetDeadline(time.Now()); err != nil {
			deps.log().Errorf("[STREAM %d] Failed to set relay deadline: %s", streamID, err)
		}
	})

	var internalPipeAddr atomic.Value
	obfConn, obfErr := wire.NewClientCodec(params.Profile, params.ObfKey)
	if obfErr != nil {
		deps.log().Errorf("[STREAM %d] OBF init failed: %v", streamID, obfErr)
		return
	}

	const maxPayload = 1600

	wg.Go(func() {
		select {
		case <-turnctx.Done():
		case <-stream.PermDead:
			deps.log().Warnf("[STREAM %d] TURN channel-bind умер - рецикл allocation", streamID)
			turncancel()
		}
		// conn2 молчит, пока приложение не шлёт: без дедлайна его читатель досидел бы
		// до первого пакета, а рецикл на простое висел бы вечно (тоннель без трафика)
		if err := conn2.SetDeadline(time.Now()); err != nil {
			deps.log().Errorf("[STREAM %d] Failed to set pipe deadline: %s", streamID, err)
		}
	})

	wg.Go(func() {
		defer turncancel()
		var buf, readSlot []byte
		if obfConn != nil {
			buf = make([]byte, obfConn.MaxWire(maxPayload))
			readSlot = buf[obfConn.HeaderLen() : obfConn.HeaderLen()+maxPayload]
		} else {
			buf = make([]byte, maxPayload)
			readSlot = buf
		}
		addrStored := false
		for {
			if turnctx.Err() != nil {
				return
			}
			n, addr1, err1 := conn2.ReadFrom(readSlot)
			if err1 != nil {
				return
			}
			if turnctx.Err() != nil {
				return
			}

			if !addrStored {
				internalPipeAddr.Store(addr1)
				addrStored = true
			}

			out := readSlot[:n]
			if obfConn != nil {
				written, wErr := obfConn.WrapInPlace(buf, n)
				if wErr != nil {
					deps.log().Errorf("[STREAM %d] OBF wrap failed: %v", streamID, wErr)
					return
				}
				out = buf[:written]
			}

			written, err1 := relayConn.WriteTo(out, peer)
			if params.TrafficStats != nil {
				params.TrafficStats.AddTx(written)
			}
			if err1 != nil {
				return
			}
		}
	})

	wg.Go(func() {
		defer turncancel()
		readBufLen := maxPayload
		if obfConn != nil {
			readBufLen = obfConn.MaxWire(maxPayload)
		}
		buf := make([]byte, readBufLen)
		for {
			n, _, err1 := relayConn.ReadFrom(buf)
			if err1 != nil {
				return
			}
			addr1 := internalPipeAddr.Load()
			if addr1 == nil {
				continue
			}

			if addr, ok := addr1.(net.Addr); ok {
				payload := buf[:n]
				if obfConn != nil {
					p, uErr := obfConn.UnwrapInPlace(buf[:n])
					if uErr != nil {
						deps.log().Errorf("[STREAM %d] OBF unwrap failed: %v (n=%d)", streamID, uErr, n)
						continue
					}
					payload = p
				}
				if params.TrafficStats != nil {
					params.TrafficStats.AddRx(len(payload))
				}
				if _, err := conn2.WriteTo(payload, addr); err != nil {
					return
				}
			}
		}
	})

	wg.Wait()
	if err := relayConn.SetDeadline(time.Time{}); err != nil {
		deps.log().Errorf("Failed to clear relay deadline: %s", err)
	}
	// conn2 достаётся следующей аллокации - с истёкшим дедлайном она читала бы пустоту
	if err := conn2.SetDeadline(time.Time{}); err != nil {
		deps.log().Errorf("Failed to clear pipe deadline: %s", err)
	}
}
