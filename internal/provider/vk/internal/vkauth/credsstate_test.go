package vkauth

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func credsPaths(t *testing.T) []string {
	t.Helper()
	return []string{filepath.Join(t.TempDir(), CredsStateFile)}
}

func sampleCreds(link string, ttl time.Duration) TurnCredentials {
	return TurnCredentials{
		Username:    "user",
		Password:    "pass",
		ServerAddrs: []string{"1.2.3.4:3478", "5.6.7.8:3478"},
		ExpiresAt:   time.Now().Add(ttl).Round(0),
		Link:        link,
	}
}

func TestCredsSurviveRestart(t *testing.T) {
	s := credsStore{paths: credsPaths(t)}
	want := sampleCreds("call-1", 5*time.Minute)
	if !s.save(0, want) {
		t.Fatal("save reported failure")
	}

	got, ok := s.load("call-1", 0)
	if !ok {
		t.Fatal("credentials not restored")
	}
	if got.Username != want.Username || got.Password != want.Password {
		t.Fatalf("creds = %q/%q, want %q/%q", got.Username, got.Password, want.Username, want.Password)
	}
	if len(got.ServerAddrs) != len(want.ServerAddrs) || got.ServerAddrs[0] != want.ServerAddrs[0] {
		t.Fatalf("addrs = %v, want %v", got.ServerAddrs, want.ServerAddrs)
	}
	if !got.ExpiresAt.Equal(want.ExpiresAt.Truncate(time.Second)) {
		t.Fatalf("expiresAt = %v, want %v", got.ExpiresAt, want.ExpiresAt.Truncate(time.Second))
	}
}

func TestCredsAreKeyedByLinkAndCache(t *testing.T) {
	s := credsStore{paths: credsPaths(t)}
	s.save(0, sampleCreds("call-1", 5*time.Minute))
	s.save(1, sampleCreds("call-1", 5*time.Minute))
	s.save(0, sampleCreds("call-2", 5*time.Minute))

	for _, tc := range []struct {
		link    string
		cacheID int
		want    bool
	}{
		{"call-1", 0, true},
		{"call-1", 1, true},
		{"call-2", 0, true},
		{"call-2", 1, false},
		{"call-3", 0, false},
	} {
		if _, ok := s.load(tc.link, tc.cacheID); ok != tc.want {
			t.Fatalf("load(%q, %d) = %v, want %v", tc.link, tc.cacheID, ok, tc.want)
		}
	}
}

// Протухание считается по стенным часам: монотонные на Android стоят во сне.
func TestExpiredCredsAreIgnored(t *testing.T) {
	s := credsStore{paths: credsPaths(t)}
	if !s.save(0, sampleCreds("call-1", -time.Second)) {
		t.Fatal("save reported failure")
	}
	if _, ok := s.load("call-1", 0); ok {
		t.Fatal("expired credentials restored")
	}
}

func TestSaveDropsExpiredEntries(t *testing.T) {
	s := credsStore{paths: credsPaths(t)}
	s.save(0, sampleCreds("stale", -time.Second))
	s.save(1, sampleCreds("fresh", 5*time.Minute))

	if n := len(s.read()); n != 1 {
		t.Fatalf("entries = %d, want 1", n)
	}
}

func TestDropRemovesOnlyItsEntry(t *testing.T) {
	s := credsStore{paths: credsPaths(t)}
	s.save(0, sampleCreds("call-1", 5*time.Minute))
	s.save(1, sampleCreds("call-1", 5*time.Minute))

	s.drop("call-1", 0)

	if _, ok := s.load("call-1", 0); ok {
		t.Fatal("dropped credentials still readable")
	}
	if _, ok := s.load("call-1", 1); !ok {
		t.Fatal("drop removed a foreign entry")
	}
}

func TestCredsStoreWithoutPathsIsNoop(t *testing.T) {
	var s credsStore
	if s.save(0, sampleCreds("call-1", 5*time.Minute)) {
		t.Fatal("empty credsStore reported a write")
	}
	if _, ok := s.load("call-1", 0); ok {
		t.Fatal("empty credsStore returned credentials")
	}
}

func TestCredsSurviveCorruptFile(t *testing.T) {
	path := credsPaths(t)[0]
	if err := os.WriteFile(path, []byte("{"), 0o600); err != nil {
		t.Fatal(err)
	}
	s := credsStore{paths: []string{path}}
	if _, ok := s.load("call-1", 0); ok {
		t.Fatal("corrupt file yielded credentials")
	}
	if !s.save(0, sampleCreds("call-1", 5*time.Minute)) {
		t.Fatal("corrupt file blocked the write")
	}
	if _, ok := s.load("call-1", 0); !ok {
		t.Fatal("credentials not restored after overwriting a corrupt file")
	}
}
