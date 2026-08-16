package config

import "github.com/samosvalishe/free-turn-proxy/internal/tunnel"

const (
	TransportTCP = "tcp"
	TransportUDP = "udp"
)

const (
	DNSModePlain = "plain"
	DNSModeDoH   = "doh"
	DNSModeAuto  = "auto"
)

const (
	DefaultListen         = "127.0.0.1:9000"
	DefaultStreams        = 10
	DefaultStreamsPerCred = 10
	DefaultTransport      = TransportTCP
	DefaultDNSMode        = DNSModeAuto
	DefaultProvider       = ProviderVK
	DefaultPlatform       = PlatformDesktop
	DefaultObfProfile     = ObfProfileNone

	DefaultServerListen = "0.0.0.0:56000"
)

func defaultRaw() raw {
	return raw{
		Listen:         DefaultListen,
		Provider:       DefaultProvider,
		N:              DefaultStreams,
		StreamsPerCred: DefaultStreamsPerCred,
		Transport:      DefaultTransport,
		ObfProfile:     string(DefaultObfProfile),
		Platform:       string(DefaultPlatform),
		DNSMode:        DefaultDNSMode,
		Routes:         false,
		TunnelMode:     string(tunnel.ModeNone),
		TunnelMTU:      tunnel.DefaultMTU,
	}
}

// Defaults возвращает конфигурацию клиента с дефолтными значениями (без peer/links).
func Defaults() Client {
	c, err := assemble(defaultRaw())
	if err != nil {
		panic("config: defaults must assemble: " + err.Error())
	}
	return *c
}

// ServerDefaults возвращает конфигурацию сервера с дефолтными значениями.
func ServerDefaults() Server {
	return Server{
		Obf:   ObfOpts{Profile: DefaultObfProfile},
		Proxy: ProxyOpts{Listen: DefaultServerListen},
	}
}
