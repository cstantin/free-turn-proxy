// Package statedir выбирает, куда клиент кладёт своё состояние между запусками.
//
// Каталоги-кандидаты перебираются по порядку: право на запись зависит от хоста
// (на Android каталог бинаря read-only), поэтому вызывающий пробует все и
// работает дальше, даже если не сохранилось нигде.
package statedir

import (
	"os"
	"path/filepath"
	"sync/atomic"
)

// dirOverride задаёт хост, которому кандидаты по умолчанию не подходят: из
// app-uid Android недоступен ни один из них (каталог бинаря read-only,
// UserConfigDir и TempDir принадлежат не приложению), и состояние молча
// оставалось бы в памяти.
//
//nolint:gochecknoglobals // ставится один раз на процесс до первого Paths
var dirOverride atomic.Pointer[string]

// SetDir переводит всё состояние клиента в dir. Пустая строка возвращает перебор
// кандидатов. Вызывать до первого Paths.
func SetDir(dir string) {
	if dir == "" {
		dirOverride.Store(nil)
		return
	}
	dirOverride.Store(&dir)
}

// Paths - пути файла name в порядке предпочтения: рядом с бинарём (desktop,
// переносимость), затем per-user UserConfigDir и TempDir.
func Paths(name string) []string {
	if dir := dirOverride.Load(); dir != nil {
		return []string{filepath.Join(*dir, name)}
	}
	seen := map[string]bool{}
	var dirs []string
	add := func(d string) {
		if d == "" || seen[d] {
			return
		}
		seen[d] = true
		dirs = append(dirs, d)
	}
	if exe, err := os.Executable(); err == nil {
		add(filepath.Dir(exe))
	}
	add(filepath.Dir(os.Args[0]))
	if cfgDir, err := os.UserConfigDir(); err == nil {
		add(filepath.Join(cfgDir, "free-turn-proxy"))
	}
	add(os.TempDir())

	paths := make([]string, 0, len(dirs))
	for _, d := range dirs {
		paths = append(paths, filepath.Join(d, name))
	}
	return paths
}

// ReadEach возвращает содержимое всех читаемых путей в порядке предпочтения:
// битый файл в начале списка не должен прятать целый в конце.
func ReadEach(paths []string) [][]byte {
	out := make([][]byte, 0, len(paths))
	for _, path := range paths {
		b, err := os.ReadFile(path) //nolint:gosec // имя фиксировано, каталог даёт хост
		if err == nil {
			out = append(out, b)
		}
	}
	return out
}

// WriteFirst пишет data по первому доступному пути; false - не открылся ни один.
func WriteFirst(paths []string, data []byte) bool {
	for _, path := range paths {
		if os.MkdirAll(filepath.Dir(path), 0o700) != nil {
			continue
		}
		if writeAtomic(path, data) == nil {
			return true
		}
	}
	return false
}

// Через временный файл: состояние пишется ради переживания убитого процесса
// (sticky-рестарт на Android), а обрезанный на полуслове JSON читается как
// "состояния нет" - ровно то, от чего файл и спасает.
func writeAtomic(path string, data []byte) error {
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil { //nolint:gosec // 0o600 для файла с секретами
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	return nil
}
