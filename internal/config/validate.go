package config

import (
	"errors"
	"fmt"
	"strings"

	"github.com/samosvalishe/free-turn-proxy/internal/tunnel"
)

// Validate проверяет валидность конфигурации Client.
func Validate(c *Client) error {
	if c == nil {
		return errors.New("nil client config")
	}
	if c.Proxy.Peer == "" {
		return errors.New("need peer address")
	}

	switch c.Provider.Name {
	case ProviderVK:
		if len(c.VK.Links) == 0 {
			return errors.New("vk: need at least one link (-links / -link)")
		}
		if c.VK.StreamsPerCred <= 0 {
			return errors.New("-streams-per-cred must be positive")
		}
		switch c.VK.Platform {
		case PlatformDesktop, PlatformMobile:
		default:
			return fmt.Errorf("invalid -platform value %q: must be %s | %s", c.VK.Platform, PlatformDesktop, PlatformMobile)
		}
	default:
		return fmt.Errorf("invalid -provider value %q: must be %s", c.Provider.Name, ProviderVK)
	}

	switch c.DNS.Mode {
	case DNSModePlain, DNSModeDoH, DNSModeAuto:
	default:
		return fmt.Errorf("invalid -dns-mode value %q: must be %s | %s | %s", c.DNS.Mode, DNSModePlain, DNSModeDoH, DNSModeAuto)
	}

	if err := validateObfProfile(c.Obf.Profile); err != nil {
		return err
	}
	if err := validateTunnel(c.Tunnel); err != nil {
		return err
	}
	return validateObfTiming(c.Obf)
}

func validateTunnel(t TunnelOpts) error {
	if t.Mode != "" && !t.Mode.Valid() {
		return fmt.Errorf("invalid tunnel mode %q: must be %s | %s | %s",
			t.Mode, tunnel.ModeNone, tunnel.ModeWG, tunnel.ModeAWG)
	}
	if !t.Enabled() {
		return nil
	}
	if strings.TrimSpace(t.Config) == "" {
		return errors.New("tunnel config is required")
	}
	if t.MTU <= 0 {
		return errors.New("tunnel MTU must be positive")
	}
	return nil
}

func ValidateServer(s *Server) error {
	if s == nil {
		return errors.New("nil server config")
	}
	if s.Proxy.Connect == "" {
		return errors.New("server address is required")
	}
	if err := validateObfProfile(s.Obf.Profile); err != nil {
		return err
	}
	return validateObfTiming(s.Obf)
}

func validateObfTiming(o ObfOpts) error {
	if o.Timing <= 0 {
		return nil
	}
	if !o.Enabled() {
		return errors.New("-obf-timing requires -obf-profile != none")
	}
	return nil
}

func validateObfProfile(p ObfProfile) error {
	switch p {
	case ObfProfileNone, ObfProfileRTPOpus, ObfProfileRTPOpus2, ObfProfileRTPOpus3:
		return nil
	default:
		return fmt.Errorf("invalid -obf-profile value %q: must be %s | %s | %s | %s", p, ObfProfileNone, ObfProfileRTPOpus, ObfProfileRTPOpus2, ObfProfileRTPOpus3)
	}
}
