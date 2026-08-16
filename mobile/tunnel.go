package mobile

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strings"
	"time"

	"github.com/samosvalishe/free-turn-proxy/internal/config"
	"github.com/samosvalishe/free-turn-proxy/internal/logx"
	"github.com/samosvalishe/free-turn-proxy/internal/netconn"
	"github.com/samosvalishe/free-turn-proxy/internal/tunnel"
	"github.com/samosvalishe/free-turn-proxy/internal/tunnel/awg"
	"github.com/samosvalishe/free-turn-proxy/internal/tunnel/bind"
	"github.com/samosvalishe/free-turn-proxy/internal/tunnel/wgconf"
)

// TunnelSnapshot - состояние userspace-туннеля. Отдельно от Snapshot: сессия и
// туннель живут своими жизнями, и мешать их счётчики в одну структуру значило бы
// заставлять UI гадать, чьи это байты.
type TunnelSnapshot struct {
	Up bool
	// RxBytes/TxBytes - трафик внутри туннеля (после расшифровки).
	RxBytes int64
	TxBytes int64
	// HandshakeAgeSec - сколько секунд назад был последний handshake;
	// -1, если его ещё не было.
	HandshakeAgeSec int64
}

func TunnelStats() *TunnelSnapshot {
	l := current.Load()
	if l == nil || l.tunnel == nil {
		return &TunnelSnapshot{HandshakeAgeSec: -1}
	}
	st, err := l.tunnel.backend.Stats()
	if err != nil {
		return &TunnelSnapshot{Up: true, HandshakeAgeSec: -1}
	}
	age := int64(-1)
	if !st.LastHandshake.IsZero() {
		age = int64(time.Since(st.LastHandshake).Seconds())
	}
	return &TunnelSnapshot{
		Up:              true,
		RxBytes:         st.RxBytes,
		TxBytes:         st.TxBytes,
		HandshakeAgeSec: age,
	}
}

// TunnelParams - параметры tun-интерфейса для платформы (VpnService.Builder на
// Android, NEPacketTunnelProvider на iOS). Списки строками через запятую -
// gomobile не экспортирует срезы.
type TunnelParams struct {
	Addresses  string // Interface.Address
	DNS        string // Interface.DNS
	AllowedIPs string // AllowedIPs всех пиров - маршруты в туннель
	MTU        int
}

// ParseTunnelConfig разбирает тот же текст, что уходит в tunnel.config, и
// отдаёт хосту параметры tun-интерфейса: туннель их не применяет, это работа
// платформы.
//
// mtu <= 0 - взять из конфига. Хост передаёт сюда то же значение, что кладёт в
// tunnel.mtu, иначе устройство и tun разъедутся.
func ParseTunnelConfig(wgText string, mtu int) (*TunnelParams, error) {
	cfg, err := wgconf.Parse(wgText)
	if err != nil {
		return nil, fmt.Errorf("parse tunnel config: %w", err)
	}
	if mtu > 0 {
		cfg.MTU = mtu
	}

	addrs := make([]string, 0, len(cfg.Addresses))
	for _, p := range cfg.Addresses {
		addrs = append(addrs, p.String())
	}
	dns := make([]string, 0, len(cfg.DNS))
	for _, a := range cfg.DNS {
		dns = append(dns, a.String())
	}
	return &TunnelParams{
		Addresses:  strings.Join(addrs, ","),
		DNS:        strings.Join(dns, ","),
		AllowedIPs: strings.Join(allowedIPs(cfg.Peers), ","),
		MTU:        cfg.MTU,
	}, nil
}

// allowedIPs собирает маршруты всех пиров без повторов - addRoute на дубле
// бросает исключение.
func allowedIPs(peers []tunnel.Peer) []string {
	out := make([]string, 0, len(peers))
	seen := make(map[netip.Prefix]struct{}, len(peers))
	for i := range peers {
		for _, p := range peers[i].AllowedIPs {
			if _, dup := seen[p]; dup {
				continue
			}
			seen[p] = struct{}{}
			out = append(out, p.String())
		}
	}
	return out
}

// tunnelParts - всё, что нужно свернуть при остановке сессии с туннелем.
type tunnelParts struct {
	backend    tunnel.Backend
	bind       *bind.SinglePeerBind
	deviceSide net.PacketConn
	relaySide  net.PacketConn
}

// buildTunnel собирает связку "устройство <-> релей" по конфигу.
//
// Между WireGuard и релеем нет сокета: пара в памяти отдаёт один конец сессии
// как локальный пир, второй оборачивается в SinglePeerBind. Отсюда нет ни
// петли через 127.0.0.1, ни необходимости защищать сокеты устройства - своих у
// него не осталось.
func buildTunnel(cfg *config.Client, logger logx.Logger) (*tunnelParts, *tunnel.Config, error) {
	tunCfg, err := wgconf.Parse(cfg.Tunnel.Config)
	if err != nil {
		return nil, nil, err
	}
	if cfg.Tunnel.MTU > 0 {
		tunCfg.MTU = cfg.Tunnel.MTU
	}
	// Режим - выбор пользователя, а не свойство файла: в wg маскировка снимается,
	// даже если конфиг принесли от AmneziaWG.
	if cfg.Tunnel.Mode == tunnel.ModeWG && tunCfg.Amnezia.Enabled() {
		logger.Warnf("tunnel: mode=wg, параметры AmneziaWG из конфига игнорируются")
		tunCfg.Amnezia = tunnel.AmneziaParams{}
	}
	// Endpoint из файла не нужен: собеседник один и достижим через релей.
	for i := range tunCfg.Peers {
		tunCfg.Peers[i].Endpoint = ""
	}

	deviceSide, relaySide := netconn.PacketPipe(tunCfg.MTU+tunnelPipeHeadroom, 0)
	parts := &tunnelParts{
		bind:       bind.NewSinglePeerBind(deviceSide),
		deviceSide: deviceSide,
		relaySide:  relaySide,
	}
	parts.backend = awg.New(awg.Deps{Bind: parts.bind, Log: logger})
	return parts, tunCfg, nil
}

// tunnelPipeHeadroom - запас поверх MTU туннеля: пакет обрастает заголовком
// WireGuard, а с маскировкой AmneziaWG - ещё и junk-префиксом.
const tunnelPipeHeadroom = 512

// close сворачивает туннель.
//
// Bind - первым: device.Close() ждёт свою читающую горутину, а та стоит в
// ReadFrom пары и просыпается только по дедлайну от Bind.Close. Обратный
// порядок работает лишь потому, что устройство закрывает Bind само, и любая
// заминка внутри device.Close оборачивается зависанием остановки.
//
// Дальше устройство (оно закрывает tun-дескриптор) и обе половины пары.
// Половину релея штатно закрывает сессия по отмене ctx; здесь - на случай
// провала старта, когда сессии ещё нет. Close идемпотентен.
func (t *tunnelParts) close() {
	if t == nil {
		return
	}
	if t.bind != nil {
		_ = t.bind.Close()
	}
	if t.backend != nil {
		_ = t.backend.Down()
	}
	if t.deviceSide != nil {
		_ = t.deviceSide.Close()
	}
	if t.relaySide != nil {
		_ = t.relaySide.Close()
	}
}

// Ядро закрывает переданный fd при остановке, поэтому хост отдаёт копию
// (Android: pfd.dup().detachFd()) и держит оригинал у себя - тогда tun
// переживает Restart и интерфейс не пересоздаётся.
func StartTunnel(configJSON string, tunFD int) error {
	if err := checkTunFD(tunFD); err != nil {
		return err
	}
	mu.Lock()
	defer mu.Unlock()
	if current.Load() != nil {
		// Владение уже наше: без этого копия хоста висела бы до конца процесса.
		awg.CloseTUNFD(tunFD)
		return errors.New("already running")
	}
	return startLocked(configJSON, tunFD, true)
}

// checkTunFD отбраковывает заведомо не-tun дескриптор до того, как ядро возьмёт
// его во владение: 0 - стандартный ввод процесса, и ранний выход закрыл бы его.
func checkTunFD(fd int) error {
	if fd <= 0 {
		return fmt.Errorf("bad tun fd %d", fd)
	}
	return nil
}
