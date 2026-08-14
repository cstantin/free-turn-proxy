package captcha

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"strconv"
	"strings"
	"testing"
)

func TestCaptchaInitSettingContentRefPrefersSettingsKey(t *testing.T) {
	setting := captchaInitSetting{
		Type:        "slider",
		Settings:    "legacy-settings",
		SettingsKey: "new-settings-key",
	}

	got := setting.contentRef()
	if got.Source != "settings_key" || got.Value != "new-settings-key" {
		t.Fatalf("contentRef = %+v, want settings_key/new-settings-key", got)
	}
}

func TestCaptchaInitSettingContentRefLegacySettings(t *testing.T) {
	setting := captchaInitSetting{
		Type:     "slider",
		Settings: "legacy-settings",
	}

	got := setting.contentRef()
	if got.Source != "captcha_settings" || got.Value != "legacy-settings" {
		t.Fatalf("contentRef = %+v, want captcha_settings/legacy-settings", got)
	}
}

func TestParseCaptchaPageSPA(t *testing.T) {
	html := `<html><head><script>
window.captchaPowResult = 'v2.' + btoa(JSON.stringify({ hash: hash, nonce: nonce }));
const powInput = "Pihj7tyAHFxdwm4t";
const difficulty = 2;
</script>
<script src="https://static.vk.ru/vkid/1.1.1384/not_robot_captcha.js"></script>
</head><body><div id="spa_root"></div></body></html>`

	page, err := parseCaptchaPage(html)
	if err != nil {
		t.Fatal(err)
	}
	if page.PowInput != "Pihj7tyAHFxdwm4t" || page.PowDifficulty != 2 {
		t.Fatalf("pow parse = %q/%d", page.PowInput, page.PowDifficulty)
	}
	if page.PowPrefix != "v2." {
		t.Fatalf("pow prefix = %q, want v2.", page.PowPrefix)
	}
	if page.ScriptURL != "https://static.vk.ru/vkid/1.1.1384/not_robot_captcha.js" {
		t.Fatalf("script url = %q", page.ScriptURL)
	}
}

func TestParseCaptchaPageMissingPoW(t *testing.T) {
	if _, err := parseCaptchaPage(`<html><body><div id="spa_root"></div></body></html>`); err == nil {
		t.Fatal("expected error when powInput/difficulty absent")
	}
}

// Формат конверта задаёт страница: незнакомая обёртка должна ронять авторешение,
// а не уезжать в check заведомо неверным hash.
func TestParseCaptchaPageMissingPowEnvelope(t *testing.T) {
	html := `<html><head><script>
const powInput = "Pihj7tyAHFxdwm4t";
const difficulty = 2;
</script></head><body></body></html>`
	if _, err := parseCaptchaPage(html); err == nil {
		t.Fatal("expected error when captchaPowResult envelope absent")
	}
}

func TestSolveCaptchaPoWRawHex(t *testing.T) {
	got, nonce := solveCaptchaPoW(context.Background(), "input", 1)
	if len(got) != 64 {
		t.Fatalf("pow = %q, want 64-hex", got)
	}
	if !strings.HasPrefix(got, "0") {
		t.Fatalf("pow = %q, want leading zero for difficulty 1", got)
	}
	again, againNonce := solveCaptchaPoW(context.Background(), "input", 1)
	if again != got || againNonce != nonce {
		t.Fatalf("pow not deterministic: %q/%d vs %q/%d", got, nonce, again, againNonce)
	}
	sum := sha256.Sum256([]byte("input" + strconv.Itoa(nonce)))
	if hex.EncodeToString(sum[:]) != got {
		t.Fatalf("pow hash does not match sha256(input+nonce)")
	}
}

func TestEncodePowResult(t *testing.T) {
	got, err := encodePowResult("v2.", powResult{Hash: "00ab", Nonce: 7, DurationMs: 42})
	if err != nil {
		t.Fatal(err)
	}
	payload, ok := strings.CutPrefix(got, "v2.")
	if !ok {
		t.Fatalf("pow result = %q, want v2. prefix", got)
	}
	raw, err := base64.StdEncoding.DecodeString(payload)
	if err != nil {
		t.Fatal(err)
	}
	// Порядок ключей копирует JSON.stringify страницы.
	if string(raw) != `{"hash":"00ab","nonce":7,"duration_ms":42}` {
		t.Fatalf("pow payload = %s", raw)
	}
}

func TestParseCaptchaInitSession(t *testing.T) {
	raw := map[string]any{"response": map[string]any{
		"show_captcha_type": "slider",
		"captcha_id":        "cid",
		"content_settings": []any{
			map[string]any{"type": "slider", "settings_key": "sliderkey"},
			map[string]any{"type": "sound", "settings_key": "soundkey"},
		},
	}}
	showType, content := parseCaptchaInitSession(raw)
	if showType != "slider" {
		t.Fatalf("show_type = %q, want slider", showType)
	}
	if content.Value != "sliderkey" || content.Source != "settings_key" {
		t.Fatalf("content = %+v, want sliderkey/settings_key", content)
	}
}

func TestParseCaptchaInitSessionCheckbox(t *testing.T) {
	raw := map[string]any{"response": map[string]any{
		"show_captcha_type": "checkbox",
		"content_settings": []any{
			map[string]any{"type": "slider", "settings_key": "k"},
		},
	}}
	showType, _ := parseCaptchaInitSession(raw)
	if showType != "checkbox" {
		t.Fatalf("show_type = %q, want checkbox", showType)
	}
}

func TestCaptchaDomainFromRedirectURI(t *testing.T) {
	tests := []struct {
		name        string
		redirectURI string
		want        string
	}{
		{
			name:        "vk com from query",
			redirectURI: "https://id.vk.ru/not_robot_captcha?domain=vk.com&session_token=x",
			want:        "vk.com",
		},
		{
			name:        "vk ru from query",
			redirectURI: "https://id.vk.ru/not_robot_captcha?domain=vk.ru&session_token=x",
			want:        "vk.ru",
		},
		{
			name:        "fallback without domain",
			redirectURI: "https://id.vk.ru/not_robot_captcha?session_token=x",
			want:        captchaDomain,
		},
		{
			name:        "fallback invalid url",
			redirectURI: "%",
			want:        captchaDomain,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := captchaDomainFromRedirectURI(tt.redirectURI); got != tt.want {
				t.Fatalf("domain = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestPickSliderAttempts(t *testing.T) {
	tests := []struct {
		name    string
		indexes []int
		limit   int
		want    []int
	}{
		{
			name:    "skips neighbours of the top guess",
			indexes: []int{20, 19, 21, 18, 40, 5},
			limit:   2,
			want:    []int{20, 40},
		},
		{
			name:    "falls back to neighbours when nothing is far enough",
			indexes: []int{20, 19, 21},
			limit:   3,
			want:    []int{20, 19, 21},
		},
		{
			name:    "limit above candidate count",
			indexes: []int{7},
			limit:   4,
			want:    []int{7},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			guesses := make([]sliderGuess, 0, len(tt.indexes))
			for _, idx := range tt.indexes {
				guesses = append(guesses, sliderGuess{Index: idx})
			}
			got := pickSliderAttempts(guesses, tt.limit)
			if len(got) != len(tt.want) {
				t.Fatalf("len = %d, want %d", len(got), len(tt.want))
			}
			for i := range tt.want {
				if got[i].Index != tt.want[i] {
					t.Fatalf("attempts = %v, want %v", got, tt.want)
				}
			}
		})
	}
}

// VK раздаёт страницу то с id.vk.ru, то с api.vk.ru: Origin от одного хоста при
// странице на другом браузер выдать не может.
func TestAPIRequestHeadersFollowPageOrigin(t *testing.T) {
	const pageQuery = "/not_robot_captcha?domain=vk.com&session_token=x&variant=popup"

	cases := []struct {
		name     string
		page     string
		apiHost  string
		wantSite string
		wantRef  string
		wantOrig string
	}{
		{
			name:     "cross-origin page",
			page:     "https://id.vk.ru" + pageQuery,
			apiHost:  "api.vk.ru",
			wantSite: "same-site",
			wantRef:  "https://id.vk.ru/",
			wantOrig: "https://id.vk.ru",
		},
		{
			name:     "same-origin page keeps full url in referer",
			page:     "https://api.vk.ru" + pageQuery,
			apiHost:  "api.vk.ru",
			wantSite: "same-origin",
			wantRef:  "https://api.vk.ru" + pageQuery,
			wantOrig: "https://api.vk.ru",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s := &captchaSession{apiHost: tc.apiHost}
			s.setPageURL(tc.page)
			got := s.apiRequestHeaders()
			if got["Sec-Fetch-Site"] != tc.wantSite {
				t.Fatalf("Sec-Fetch-Site = %q, want %q", got["Sec-Fetch-Site"], tc.wantSite)
			}
			if got["Referer"] != tc.wantRef {
				t.Fatalf("Referer = %q, want %q", got["Referer"], tc.wantRef)
			}
			if got["Origin"] != tc.wantOrig {
				t.Fatalf("Origin = %q, want %q", got["Origin"], tc.wantOrig)
			}
		})
	}
}

// Пока challenge есть в window.init, виджет не ходит в initSession - и мы тоже.
func TestParseCaptchaInitGlobal(t *testing.T) {
	html := `<script>window.init = {"hosts":{"api":"api.vk.ru"},` +
		`"data":{"show_captcha_type":"slider","captcha_settings":[{"type":"slider","settings_key":"a2V5"}]},` +
		`"tail":{"brace":"}"}};</script>`
	got := parseCaptchaInitGlobal(html)
	if !got.Found || got.APIHost != "api.vk.ru" || got.ShowType != "slider" {
		t.Fatalf("init = %+v", got)
	}
	if got.Content.Value != "a2V5" || got.Content.Source != "settings_key" {
		t.Fatalf("content = %+v", got.Content)
	}
}

// Без window.init виджет запрашивает initSession сам - и Found обязан быть false.
func TestParseCaptchaInitGlobalAbsent(t *testing.T) {
	if got := parseCaptchaInitGlobal(`<script>var x = 1;</script>`); got.Found || got.APIHost != "" {
		t.Fatalf("init = %+v, want empty", got)
	}
}

// Битый redirect_uri не должен оставлять Origin пустым.
func TestSetPageURLFallsBackToWidgetOrigin(t *testing.T) {
	s := &captchaSession{apiHost: "api.vk.ru"}
	s.setPageURL("not-a-url")
	if s.pageOrigin != captchaAPIOrigin || s.pageURL != captchaAPIOrigin+"/" {
		t.Fatalf("page = %q / %q", s.pageOrigin, s.pageURL)
	}
}
