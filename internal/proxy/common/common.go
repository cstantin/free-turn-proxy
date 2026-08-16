// Package common содержит общие вспомогательные функции для udprelay и tcpfwd.
package common

import (
	"context"
	"errors"
	"fmt"
	"net"

	"github.com/samosvalishe/free-turn-proxy/internal/transport/turndial"
	"github.com/samosvalishe/free-turn-proxy/internal/wire"
)

// GetCredsFunc разрешает TURN-реквизиты для streamID.
type GetCredsFunc func(ctx context.Context, streamID int) (user, pass string, rawURLs []string, err error)

// DialTURN запрашивает учетные данные и подключается к первому доступному TURN-серверу из списка кандидатов.
func DialTURN(ctx context.Context, host, port string, udp bool, peer *net.UDPAddr, streamID int, getCreds GetCredsFunc) (*turndial.Stream, error) {
	user, pass, rawURLs, err := getCreds(ctx, streamID)
	if err != nil {
		return nil, fmt.Errorf("get TURN creds: %w", err)
	}
	if len(rawURLs) == 0 {
		return nil, fmt.Errorf("no TURN candidates")
	}
	if host != "" {
		rawURLs = rawURLs[:1]
	}
	var errs []error
	for _, rawURL := range rawURLs {
		stream, derr := turndial.Open(ctx, turndial.Config{
			HostOverride: host,
			PortOverride: port,
			TransportUDP: udp,
		}, peer, user, pass, rawURL)
		if derr == nil {
			return stream, nil
		}
		errs = append(errs, fmt.Errorf("%s: %w", rawURL, derr))
		if ctx.Err() != nil {
			break
		}
	}
	return nil, fmt.Errorf("all TURN candidates failed: %w", errors.Join(errs...))
}

// NewClientObf возвращает клиентский wire.Codec для профиля obf.
func NewClientObf(profile string, key []byte) (wire.Codec, error) {
	return wire.NewClientCodec(profile, key)
}
