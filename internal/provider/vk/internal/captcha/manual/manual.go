package manual

import (
	"bytes"
	"compress/gzip"
	"context"
	_ "embed"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httputil"
	neturl "net/url"
	"os/exec"
	"regexp"
	"runtime"
	"strings"
	"time"

	"github.com/samosvalishe/free-turn-proxy/internal/client/ish"
	"github.com/samosvalishe/free-turn-proxy/internal/logx"
	"github.com/samosvalishe/free-turn-proxy/internal/provider/vk/internal/browserprofile"
	"github.com/samosvalishe/free-turn-proxy/internal/provider/vk/internal/captcha"
	"github.com/samosvalishe/free-turn-proxy/internal/provider/vk/internal/personanet"
)

// Debug включает логирование проксируемого браузерного трафика.
var Debug bool

var Log logx.Logger = logx.Nop()

func SetLogger(l logx.Logger) { Log = logx.OrNop(l) }

const captchaListenPort = "8765"

//go:embed inject.js
var injectJS string

func injectScriptTag(localOrigin, upstreamOrigin string) string {
	cfg, _ := json.Marshal(map[string]string{"local": localOrigin, "upstream": upstreamOrigin})
	return "\n<script>window.__ftpCaptcha=" + string(cfg) + ";</script>\n<script>\n" + injectJS + "</script>\n"
}

type browserCommand struct {
	name string
	args []string
}

func localCaptchaOrigin() string {
	return "http://localhost:" + captchaListenPort
}

func localCaptchaListenAddrs() []string {
	return []string{
		"127.0.0.1:" + captchaListenPort,
		"[::1]:" + captchaListenPort,
	}
}

func localCaptchaHosts() []string {
	return []string{
		"localhost:" + captchaListenPort,
		"127.0.0.1:" + captchaListenPort,
		"[::1]:" + captchaListenPort,
	}
}

var blockedProxyHosts = []string{
	"ads.vk.com", "ads.vk.ru",
	"top-fwz1.mail.ru", "r0.mradx.net",
	"sdk-api.apptracer.ru", "stats.vk-portal.net",
}

func isAllowedProxyHost(hostname string) bool {
	for _, blocked := range blockedProxyHosts {
		if strings.EqualFold(hostname, blocked) {
			return false
		}
	}
	allowed := []string{
		".vk.com", ".vk.ru", ".vkontakte.ru",
		".userapi.com", ".okcdn.ru", ".mycdn.me",
		".api.vk.com", ".api.vk.ru",
	}
	for _, suffix := range allowed {
		if strings.HasSuffix(hostname, suffix) || hostname == suffix[1:] {
			return true
		}
	}
	return false
}

func isLocalCaptchaHost(host string) bool {
	for _, localHost := range localCaptchaHosts() {
		if strings.EqualFold(host, localHost) {
			return true
		}
	}
	return false
}

func localCaptchaURLForTarget(targetURL *neturl.URL) string {
	localURL := &neturl.URL{
		Scheme:   "http",
		Host:     "localhost:" + captchaListenPort,
		Path:     targetURL.Path,
		RawPath:  targetURL.RawPath,
		RawQuery: targetURL.RawQuery,
	}
	if localURL.Path == "" {
		localURL.Path = "/"
	}
	return localURL.String()
}

func targetOrigin(targetURL *neturl.URL) string {
	return targetURL.Scheme + "://" + targetURL.Host
}

func isSafeLocalRedirectPath(raw string) bool {
	if raw == "" || raw[0] != '/' {
		return false
	}
	if len(raw) > 1 && (raw[1] == '/' || raw[1] == '\\') {
		return false
	}
	return true
}

func rewriteProxyRedirectLocation(raw string, targetURL *neturl.URL) (string, bool) {
	if isSafeLocalRedirectPath(raw) {
		return raw, true
	}

	parsed, err := neturl.Parse(raw)
	if err != nil {
		return "", false
	}
	if !strings.EqualFold(parsed.Scheme, targetURL.Scheme) || !strings.EqualFold(parsed.Host, targetURL.Host) {
		return "", false
	}

	return localCaptchaURLForTarget(parsed), true
}

func rewriteProxyHeaderURL(raw string, targetURL *neturl.URL) string {
	if raw == "" {
		return raw
	}
	parsed, err := neturl.Parse(raw)
	if err != nil {
		return raw
	}
	if parsed.Scheme != "http" || !isLocalCaptchaHost(parsed.Host) {
		return raw
	}
	parsed.Scheme = targetURL.Scheme
	parsed.Host = targetURL.Host
	return parsed.String()
}

func rewriteProxyRequest(req *http.Request, targetURL *neturl.URL) {
	req.URL.Scheme = targetURL.Scheme
	req.URL.Host = targetURL.Host
	if req.URL.Path == "" {
		req.URL.Path = targetURL.Path
	}
	req.Host = targetURL.Host

	req.Header.Del("Accept-Encoding")
	req.Header.Del("TE") // отключить transfer encoding compression
	for _, h := range []string{
		"X-Requested-With",
		"X-Android-Package",
		"X-Android-Cert",
		"X-Client-Data",
		"X-Discord-Locale",
		"X-Discord-Timezone",
		"Save-Data",
		"Purpose",
		"Sec-Purpose",
	} {
		req.Header.Del(h)
	}
	for _, headerName := range []string{"Origin", "Referer"} {
		if rewritten := rewriteProxyHeaderURL(req.Header.Get(headerName), targetURL); rewritten != "" {
			req.Header.Set(headerName, rewritten)
		} else {
			req.Header.Del(headerName)
		}
	}
}

func extractSuccessToken(body []byte) string {
	var payload struct {
		Response struct {
			SuccessToken string `json:"success_token"`
		} `json:"response"`
	}
	if err := json.Unmarshal(body, &payload); err != nil {
		return ""
	}
	return payload.Response.SuccessToken
}

func rewriteProxyCookies(header http.Header) {
	cookies := (&http.Response{Header: header}).Cookies()
	if len(cookies) == 0 {
		return
	}
	header.Del("Set-Cookie")
	for _, cookie := range cookies {
		cookie.Domain = ""
		cookie.Secure = false
		cookie.Partitioned = false
		if cookie.SameSite == http.SameSiteNoneMode || cookie.SameSite == http.SameSiteStrictMode {
			cookie.SameSite = http.SameSiteLaxMode
		}
		header.Add("Set-Cookie", cookie.String())
	}
}

var htmlURLAttrDoubleRe = regexp.MustCompile(`(?i)((?:src|href|action)\s*=\s*)"((?:https?:)?//[^"]+)"`)
var htmlURLAttrSingleRe = regexp.MustCompile(`(?i)((?:src|href|action)\s*=\s*)'((?:https?:)?//[^']+)'`)
var htmlScriptContentRe = regexp.MustCompile(`(?is)(<script[^>]*>)(.*?)(</script>)`)
var htmlStyleContentRe = regexp.MustCompile(`(?is)(<style[^>]*>)(.*?)(</style>)`)

func rewriteHTMLAttrsServerSide(html string, targetURL *neturl.URL) string {
	localOrigin := localCaptchaOrigin()
	upstreamOrigin := targetOrigin(targetURL)

	rewriteURL := func(rawURL string) string {
		absURL := rawURL
		if strings.HasPrefix(rawURL, "//") {
			absURL = targetURL.Scheme + ":" + rawURL
		}
		if strings.HasPrefix(absURL, upstreamOrigin) {
			return localOrigin + absURL[len(upstreamOrigin):]
		}
		if strings.HasPrefix(absURL, localOrigin) {
			return rawURL
		}
		return "/generic_proxy?proxy_url=" + neturl.QueryEscape(absURL)
	}

	var placeholders = make(map[string]string)

	html = htmlScriptContentRe.ReplaceAllStringFunc(html, func(match string) string {
		groups := htmlScriptContentRe.FindStringSubmatch(match)
		if len(groups) < 4 {
			return match
		}
		id := fmt.Sprintf("@@CONTENT_%d@@", len(placeholders))
		placeholders[id] = groups[2]
		return groups[1] + id + groups[3]
	})

	html = htmlStyleContentRe.ReplaceAllStringFunc(html, func(match string) string {
		groups := htmlStyleContentRe.FindStringSubmatch(match)
		if len(groups) < 4 {
			return match
		}
		id := fmt.Sprintf("@@CONTENT_%d@@", len(placeholders))
		placeholders[id] = groups[2]
		return groups[1] + id + groups[3]
	})

	html = htmlURLAttrDoubleRe.ReplaceAllStringFunc(html, func(match string) string {
		groups := htmlURLAttrDoubleRe.FindStringSubmatch(match)
		if len(groups) < 3 {
			return match
		}
		return groups[1] + `"` + rewriteURL(groups[2]) + `"`
	})

	html = htmlURLAttrSingleRe.ReplaceAllStringFunc(html, func(match string) string {
		groups := htmlURLAttrSingleRe.FindStringSubmatch(match)
		if len(groups) < 3 {
			return match
		}
		return groups[1] + `'` + rewriteURL(groups[2]) + `'`
	})

	for id, content := range placeholders {
		html = strings.Replace(html, id, content, 1)
	}

	return html
}

func rewriteCaptchaHTML(html string, targetURL *neturl.URL) string {
	localOrigin := localCaptchaOrigin()
	upstreamOrigin := targetOrigin(targetURL)

	html = strings.ReplaceAll(html, upstreamOrigin, localOrigin)
	html = rewriteHTMLAttrsServerSide(html, targetURL)

	script := injectScriptTag(localOrigin, upstreamOrigin)

	switch {
	case strings.Contains(html, "<head>"):
		return strings.Replace(html, "<head>", "<head>"+script, 1)
	case strings.Contains(html, "</head>"):
		return strings.Replace(html, "</head>", script+"</head>", 1)
	case strings.Contains(html, "</body>"):
		return strings.Replace(html, "</body>", script+"</body>", 1)
	default:
		return html + script
	}
}

func startCaptchaServer(srv *http.Server, logPrefix string) error {
	var listenErrs []string
	var listening bool

	for _, addr := range localCaptchaListenAddrs() {
		listener, err := net.Listen("tcp", addr)
		if err != nil {
			listenErrs = append(listenErrs, fmt.Sprintf("%s (%v)", addr, err))
			continue
		}
		listening = true
		wrappedListener, err := ish.WrapListener(listener)
		if err != nil {
			Log.Warnf("%s: failed to wrap listener for iSH: %v", logPrefix, err)
			wrappedListener = listener
		}
		go func(listener net.Listener) {
			if err := srv.Serve(listener); err != nil && !errors.Is(err, http.ErrServerClosed) {
				Log.Errorf("%s: %s", logPrefix, err)
			}
		}(wrappedListener)
	}

	if listening {
		return nil
	}

	return fmt.Errorf("captcha listeners failed: %s", strings.Join(listenErrs, "; "))
}

func runCaptchaServerAndWait(ctx context.Context, handler http.Handler, captchaURL string, keyCh <-chan string, logPrefix string, present func(string)) (string, error) {
	srv := &http.Server{Handler: handler, ReadHeaderTimeout: 10 * time.Second}

	if err := startCaptchaServer(srv, logPrefix); err != nil {
		return "", err
	}

	defer func() { //nolint:contextcheck
		shutCtx, shutCancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer shutCancel()
		if err := srv.Shutdown(shutCtx); err != nil {
			Log.Warnf("%s: shutdown warning: %v", logPrefix, err)
		}
	}()

	fmt.Println("\n==============================================")
	fmt.Println("ACTION REQUIRED: MANUAL CAPTCHA SOLVING NEEDED")
	fmt.Println("==============================================")
	fmt.Println("Opening browser for manual verification...")
	fmt.Println("URL:", captchaURL)
	fmt.Println("Waiting for completion in browser...")
	fmt.Println("==============================================")

	present(captchaURL)

	select {
	case <-ctx.Done():
		return "", ctx.Err()
	case token := <-keyCh:
		if token == "" {
			return "", errors.New("empty captcha token")
		}
		fmt.Println("Captcha solved successfully!")
		return token, nil
	}
}

func notifyKey(keyCh chan<- string, key string) {
	if key != "" {
		select {
		case keyCh <- key:
		default:
		}
	}
}

type loggingTransport struct {
	rt      http.RoundTripper
	started time.Time
}

func (t *loggingTransport) elapsed() time.Duration {
	return time.Since(t.started).Truncate(time.Millisecond)
}

func (t *loggingTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	start := time.Now()
	resp, err := t.rt.RoundTrip(req)
	if err != nil {
		Log.Errorf("[Captcha Proxy] HTTP OUT: %s %s ERROR: %v (since start: %v, roundtrip: %v, nav: %s)",
			req.Method, captcha.SafeURL(req.URL.String()), err, t.elapsed(), time.Since(start).Truncate(time.Millisecond), navSummary(req))
		return nil, err
	}
	Log.Debugf("[Captcha Proxy] HTTP OUT: %s %s -> %d (since start: %v, roundtrip: %v, nav: %s)",
		req.Method, captcha.SafeURL(req.URL.String()), resp.StatusCode, t.elapsed(), time.Since(start).Truncate(time.Millisecond), navSummary(req))
	return resp, nil
}

func navSummary(req *http.Request) string {
	return captcha.NavSummary(
		req.Header.Get("Sec-Fetch-Dest"),
		req.Header.Get("Sec-Fetch-Site"),
		req.Header.Get("Referer"))
}

func SolveViaProxy(ctx context.Context, redirectURI string, dialer net.Dialer, profile browserprofile.Profile) (string, error) {
	return solveViaProxy(ctx, redirectURI, dialer, profile, openBrowser)
}

func SolveViaProxyWithPresenter(ctx context.Context, redirectURI string, dialer net.Dialer, profile browserprofile.Profile, present func(string)) (string, error) {
	if present == nil {
		present = func(string) {}
	}
	return solveViaProxy(ctx, redirectURI, dialer, profile, present)
}

func solveViaProxy(ctx context.Context, redirectURI string, dialer net.Dialer, profile browserprofile.Profile, present func(string)) (string, error) {
	keyCh := make(chan string, 1)

	targetURL, err := neturl.Parse(redirectURI)
	if err != nil {
		return "", fmt.Errorf("invalid redirect URI: %v", err)
	}

	client, err := personanet.NewClient(profile, dialer, nil, personanet.NoFollowRedirects())
	if err != nil {
		return "", fmt.Errorf("captcha proxy client: %w", err)
	}
	transport := &loggingTransport{rt: personanet.ProxyRoundTripper(client), started: time.Now()}

	proxy := &httputil.ReverseProxy{
		Transport: transport,
		Rewrite: func(req *httputil.ProxyRequest) {
			rewriteProxyRequest(req.Out, targetURL)
		},
		ErrorHandler: func(w http.ResponseWriter, r *http.Request, err error) {
			Log.Errorf("[Captcha Proxy] %s %s: %v", r.Method, r.URL.String(), err)
			http.Error(w, "ошибка прокси капчи", http.StatusBadGateway)
		},
		ModifyResponse: func(res *http.Response) error {
			rewriteProxyCookies(res.Header)

			if res.StatusCode >= 300 && res.StatusCode < 400 {
				if loc := res.Header.Get("Location"); loc != "" {
					if rewritten, ok := rewriteProxyRedirectLocation(loc, targetURL); ok {
						res.Header.Set("Location", rewritten)
					} else {
						res.Header.Del("Location")
					}
				}
			}

			contentType := res.Header.Get("Content-Type")
			shouldInspectBody := strings.Contains(contentType, "text/html") ||
				strings.Contains(contentType, "application/xhtml+xml") ||
				strings.Contains(res.Request.URL.Path, "captchaNotRobot.check")

			if !shouldInspectBody {
				return nil
			}

			reader := res.Body
			if res.Header.Get("Content-Encoding") == "gzip" {
				gzReader, err := gzip.NewReader(res.Body)
				if err == nil {
					reader = gzReader
					defer gzReader.Close()
				}
			}

			bodyBytes, err := io.ReadAll(reader)
			if err != nil {
				return err
			}
			res.Body.Close()

			if strings.Contains(res.Request.URL.Path, "captchaNotRobot.check") {
				notifyKey(keyCh, extractSuccessToken(bodyBytes))
			}

			if strings.Contains(contentType, "text/html") {
				for _, headerName := range []string{
					"Content-Security-Policy",
					"Content-Security-Policy-Report-Only",
					"X-Content-Security-Policy",
					"X-WebKit-CSP",
					"Cross-Origin-Opener-Policy",
					"Cross-Origin-Embedder-Policy",
					"Cross-Origin-Resource-Policy",
					"X-Frame-Options",
					"Strict-Transport-Security",
					"Alt-Svc",
				} {
					res.Header.Del(headerName)
				}

				bodyBytes = []byte(rewriteCaptchaHTML(string(bodyBytes), targetURL))
			}

			res.Header.Del("Content-Encoding")
			res.Body = io.NopCloser(bytes.NewReader(bodyBytes))
			res.ContentLength = int64(len(bodyBytes))
			res.Header.Set("Content-Length", fmt.Sprint(len(bodyBytes)))

			return nil
		},
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/local-captcha-result", func(w http.ResponseWriter, r *http.Request) {
		token := r.FormValue("token")
		if token != "" {
			notifyKey(keyCh, token)
		}
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Content-Type", "text/plain")
		_, _ = fmt.Fprint(w, "ok")
	})

	mux.HandleFunc("/generic_proxy", func(w http.ResponseWriter, r *http.Request) {
		targetAuthURL := r.URL.Query().Get("proxy_url")
		targetParsed, err := neturl.Parse(targetAuthURL)
		if err != nil || targetParsed.Host == "" {
			http.Error(w, "Bad URL", http.StatusBadRequest)
			return
		}
		if !isAllowedProxyHost(targetParsed.Hostname()) {
			http.Error(w, "Forbidden host", http.StatusForbidden)
			return
		}
		genericReverse := &httputil.ReverseProxy{
			Transport: transport,
			Rewrite: func(req *httputil.ProxyRequest) {
				req.Out.URL.Path = targetParsed.Path
				req.Out.URL.RawQuery = targetParsed.RawQuery
				rewriteProxyRequest(req.Out, targetParsed)
			},
			ModifyResponse: func(res *http.Response) error {
				for _, h := range []string{
					"Content-Security-Policy",
					"Content-Security-Policy-Report-Only",
					"X-Content-Security-Policy",
					"X-WebKit-CSP",
					"Cross-Origin-Opener-Policy",
					"Cross-Origin-Embedder-Policy",
					"Cross-Origin-Resource-Policy",
					"X-Frame-Options",
					"Strict-Transport-Security",
				} {
					res.Header.Del(h)
				}
				res.Header.Set("Access-Control-Allow-Origin", "*")

				if strings.Contains(targetAuthURL, "captchaNotRobot.check") {
					bodyBytes, readErr := io.ReadAll(res.Body)
					if readErr == nil {
						_ = res.Body.Close()
						res.Body = io.NopCloser(bytes.NewReader(bodyBytes))
						res.ContentLength = int64(len(bodyBytes))
						res.Header.Set("Content-Length", fmt.Sprint(len(bodyBytes)))
						notifyKey(keyCh, extractSuccessToken(bodyBytes))
					}
				}

				return nil
			},
		}
		genericReverse.ServeHTTP(w, r)
	})

	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/" && targetURL.Path != "" && targetURL.Path != "/" && r.URL.RawQuery == "" {
			http.Redirect(w, r, localCaptchaURLForTarget(targetURL), http.StatusTemporaryRedirect)
			return
		}
		proxy.ServeHTTP(w, r)
	})

	return runCaptchaServerAndWait(ctx, mux, localCaptchaURLForTarget(targetURL), keyCh, "proxy HTTP server error", present)
}

func openBrowser(url string) {
	for _, cmd := range browserOpenCommands(runtime.GOOS, url) {
		if err := exec.Command(cmd.name, cmd.args...).Start(); err == nil {
			return
		}
	}
}

func browserOpenCommands(goos string, url string) []browserCommand {
	switch goos {
	case "windows":
		return []browserCommand{
			{name: "rundll32", args: []string{"url.dll,FileProtocolHandler", url}},
			// fallback с пустым title для 'start' - обход проблем с кавычками
			{name: "cmd", args: []string{"/c", "start", "", url}},
		}
	case "darwin":
		return []browserCommand{{name: "open", args: []string{url}}}
	case "linux":
		return []browserCommand{
			{name: "xdg-open", args: []string{url}},
			{name: "gio", args: []string{"open", url}},
		}
	case "android":
		return []browserCommand{
			{name: "termux-open-url", args: []string{url}},
			{name: "/system/bin/am", args: []string{"start", "-a", "android.intent.action.VIEW", "-d", url}},
			{name: "am", args: []string{"start", "-a", "android.intent.action.VIEW", "-d", url}},
			{name: "xdg-open", args: []string{url}},
		}
	case "ios":
		return []browserCommand{
			{name: "open", args: []string{url}},
			{name: "uiopen", args: []string{url}},
		}
	}
	return nil
}
