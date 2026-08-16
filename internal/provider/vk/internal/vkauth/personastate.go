package vkauth

import (
	"encoding/json"
	"sync"

	"github.com/samosvalishe/free-turn-proxy/internal/statedir"
)

// PersonaStateFile - имя файла с поколением персоны рядом с client_config.json.
const PersonaStateFile = "vk_persona.json"

type personaState struct {
	Seed string `json:"seed"`
	Gen  int    `json:"gen"`
}

type genStore struct {
	paths []string
}

func (s genStore) load(seed string) int {
	best := 0
	for _, b := range statedir.ReadEach(s.paths) {
		var st personaState
		if json.Unmarshal(b, &st) == nil && st.Seed == seed && st.Gen > best {
			best = st.Gen
		}
	}
	return best
}

//nolint:gochecknoglobals
var genMu sync.Mutex

func (s genStore) save(seed string, gen int) bool {
	if len(s.paths) == 0 {
		return false
	}
	genMu.Lock()
	defer genMu.Unlock()
	if gen <= s.load(seed) {
		return true
	}
	b, err := json.Marshal(personaState{Seed: seed, Gen: gen})
	if err != nil {
		return false
	}
	return statedir.WriteFirst(s.paths, b)
}
