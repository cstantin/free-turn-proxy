// Package clientid хранит постоянный идентификатор клиента между запусками.
//
// ID участвует в allowlist сервера (-clients-file) и служит seed'ом отпечатка
// VK-персоны, поэтому ротация на каждый запуск ломает и авторизацию, и
// стабильность fingerprint. Пути-кандидаты задаёт хост: у desktop это каталог
// рядом с бинарём, у мобильного приложения - его private storage.
package clientid

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"

	"github.com/samosvalishe/free-turn-proxy/internal/statedir"
)

const fileName = "client_config.json"

type fileFormat struct {
	ClientID string `json:"client_id"`
}

// Resolve возвращает ID клиента: заданный явно, прочитанный из первого
// читаемого файла или новый сгенерированный.
//
// persisted=false, когда новый ID не удалось записать ни по одному пути -
// вызывающий решает, шуметь ли об этом (такой ID живёт до перезапуска).
func Resolve(id string, paths []string) (resolved string, persisted bool, err error) {
	if id != "" {
		return id, true, nil
	}

	for _, b := range statedir.ReadEach(paths) {
		var f fileFormat
		if json.Unmarshal(b, &f) == nil && f.ClientID != "" {
			return f.ClientID, true, nil
		}
	}

	buf := make([]byte, 16)
	if _, rerr := rand.Read(buf); rerr != nil {
		return "", false, fmt.Errorf("generate client id: %w", rerr)
	}
	newID := hex.EncodeToString(buf)

	// Маршалинг структуры из одной строки не падает.
	b, _ := json.MarshalIndent(fileFormat{ClientID: newID}, "", "  ")
	return newID, statedir.WriteFirst(paths, b), nil
}

func DefaultPaths() []string { return statedir.Paths(fileName) }
