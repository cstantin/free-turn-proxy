package uri

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
)

const scheme = "freeturn://"

const currentVersion = 1

// Config представляет параметры подключения из share-ссылки freeturn://.
type Config struct {
	Version        int
	Provider       string
	Peer           string
	Transport      string
	ObfProfile     string
	ObfKey         string
	N              int
	StreamsPerCred int
	ClientID       string
	Listen         string
	DNSMode        string
	DNSServers     string
	ManualCaptcha  bool
	Comment        string
}

// wire - JSON-схема freeturn:// ссылок.
type wire struct {
	V              int    `json:"v"`
	Provider       string `json:"provider"`
	Peer           string `json:"peer"`
	Transport      string `json:"transport,omitempty"`
	Obf            string `json:"obf,omitempty"`
	Key            string `json:"key,omitempty"`
	N              int    `json:"n,omitempty"`
	StreamsPerCred int    `json:"spc,omitempty"`
	ClientID       string `json:"cid,omitempty"`
	Listen         string `json:"listen,omitempty"`
	DNSMode        string `json:"dns,omitempty"`
	DNSServers     string `json:"dnss,omitempty"`
	ManualCaptcha  bool   `json:"mcap,omitempty"`
	Name           string `json:"name,omitempty"`
}

// Parse разбирает строку freeturn://<base64url(json)>.
func Parse(s string) (*Config, error) {
	if !strings.HasPrefix(s, scheme) {
		return nil, errors.New("invalid scheme, expected freeturn://")
	}
	payload := strings.TrimPrefix(s, scheme)
	if payload == "" {
		return nil, errors.New("empty payload")
	}

	raw, err := base64.RawURLEncoding.DecodeString(payload)
	if err != nil {
		return nil, errors.New("invalid base64 payload")
	}

	var w wire
	if err := json.Unmarshal(raw, &w); err != nil {
		return nil, errors.New("invalid json payload")
	}
	if w.V != currentVersion {
		return nil, errors.New("unsupported link version")
	}
	if w.Provider == "" {
		return nil, errors.New("missing provider")
	}
	if w.Peer == "" {
		return nil, errors.New("missing peer")
	}

	return &Config{
		Version:        w.V,
		Provider:       w.Provider,
		Peer:           w.Peer,
		Transport:      w.Transport,
		ObfProfile:     w.Obf,
		ObfKey:         w.Key,
		N:              w.N,
		StreamsPerCred: w.StreamsPerCred,
		ClientID:       w.ClientID,
		Listen:         w.Listen,
		DNSMode:        w.DNSMode,
		DNSServers:     w.DNSServers,
		ManualCaptcha:  w.ManualCaptcha,
		Comment:        w.Name,
	}, nil
}

// String кодирует Config в freeturn://<base64url(json)>.
func (c *Config) String() string {
	w := wire{
		V:              currentVersion,
		Provider:       c.Provider,
		Peer:           c.Peer,
		Transport:      c.Transport,
		N:              c.N,
		StreamsPerCred: c.StreamsPerCred,
		ClientID:       c.ClientID,
		Listen:         c.Listen,
		DNSMode:        c.DNSMode,
		DNSServers:     c.DNSServers,
		ManualCaptcha:  c.ManualCaptcha,
		Name:           c.Comment,
	}
	if c.ObfProfile != "" && c.ObfProfile != "none" {
		w.Obf = c.ObfProfile
		w.Key = c.ObfKey
	}

	raw, err := json.Marshal(w)
	if err != nil {
		return ""
	}
	return scheme + base64.RawURLEncoding.EncodeToString(raw)
}
