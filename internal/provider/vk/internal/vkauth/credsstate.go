package vkauth

import (
	"encoding/json"
	"sync"
	"time"

	"github.com/samosvalishe/free-turn-proxy/internal/statedir"
)

// CredsStateFile - имя файла с кэшем TURN-реквизитов рядом с vk_persona.json.
const CredsStateFile = "vk_turn_creds.json"

type credsEntry struct {
	Link        string   `json:"link"`
	CacheID     int      `json:"cacheId"`
	Username    string   `json:"username"`
	Password    string   `json:"password"`
	ServerAddrs []string `json:"serverAddrs"`
	ExpiresAt   int64    `json:"expiresAt"`
}

type credsState struct {
	Entries []credsEntry `json:"entries"`
}

type credsStore struct {
	paths []string
}

//nolint:gochecknoglobals
var credsMu sync.Mutex

type credsKey struct {
	link    string
	cacheID int
}

func (s credsStore) read() []credsEntry {
	var out []credsEntry
	seen := map[credsKey]int{}
	for _, b := range statedir.ReadEach(s.paths) {
		var st credsState
		if json.Unmarshal(b, &st) != nil {
			continue
		}
		for _, e := range st.Entries {
			k := credsKey{link: e.Link, cacheID: e.CacheID}
			i, dup := seen[k]
			if !dup {
				seen[k] = len(out)
				out = append(out, e)
				continue
			}
			if e.ExpiresAt > out[i].ExpiresAt {
				out[i] = e
			}
		}
	}
	return out
}

func (s credsStore) keep(link string, cacheID int) []credsEntry {
	now := time.Now().Unix()
	var out []credsEntry
	for _, e := range s.read() {
		if e.ExpiresAt <= now || (e.Link == link && e.CacheID == cacheID) {
			continue
		}
		out = append(out, e)
	}
	return out
}

func (s credsStore) write(entries []credsEntry) bool {
	b, err := json.Marshal(credsState{Entries: entries})
	if err != nil {
		return false
	}
	return statedir.WriteFirst(s.paths, b)
}

func (s credsStore) load(link string, cacheID int) (TurnCredentials, bool) {
	if len(s.paths) == 0 {
		return TurnCredentials{}, false
	}
	credsMu.Lock()
	defer credsMu.Unlock()

	now := time.Now().Unix()
	for _, e := range s.read() {
		if e.Link != link || e.CacheID != cacheID || len(e.ServerAddrs) == 0 || e.ExpiresAt <= now {
			continue
		}
		return TurnCredentials{
			Username:    e.Username,
			Password:    e.Password,
			ServerAddrs: e.ServerAddrs,
			ExpiresAt:   time.Unix(e.ExpiresAt, 0),
			Link:        e.Link,
		}, true
	}
	return TurnCredentials{}, false
}

func (s credsStore) save(cacheID int, c TurnCredentials) bool {
	if len(s.paths) == 0 || c.Link == "" || len(c.ServerAddrs) == 0 {
		return false
	}
	credsMu.Lock()
	defer credsMu.Unlock()

	return s.write(append(s.keep(c.Link, cacheID), credsEntry{
		Link:        c.Link,
		CacheID:     cacheID,
		Username:    c.Username,
		Password:    c.Password,
		ServerAddrs: c.ServerAddrs,
		ExpiresAt:   c.ExpiresAt.Unix(),
	}))
}

func (s credsStore) drop(link string, cacheID int) {
	if len(s.paths) == 0 || link == "" {
		return
	}
	credsMu.Lock()
	defer credsMu.Unlock()

	s.write(s.keep(link, cacheID))
}
