package server

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"testing/fstest"
)

func TestGuard(t *testing.T) {
	h := New(Options{Static: fstest.MapFS{"index.html": {Data: []byte("hi")}}, Version: "test"})
	body := `{"host":"127.0.0.1","ports":[1]}`
	cases := []struct {
		name, host, origin, ctype string
		want                      int
	}{
		{"same origin ok", "127.0.0.1:8587", "http://127.0.0.1:8587", "application/json", 200},
		{"no origin ok", "localhost:8587", "", "application/json", 200},
		{"dns rebinding blocked", "evil.example:8587", "", "application/json", 403},
		{"cross-site blocked", "127.0.0.1:8587", "https://evil.example", "application/json", 403},
		{"form post blocked", "127.0.0.1:8587", "", "text/plain", 415},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			r := httptest.NewRequest("POST", "/api/ports", strings.NewReader(body))
			r.Host = c.host
			if c.origin != "" {
				r.Header.Set("Origin", c.origin)
			}
			r.Header.Set("Content-Type", c.ctype)
			w := httptest.NewRecorder()
			h.ServeHTTP(w, r)
			if w.Code != c.want {
				t.Fatalf("got %d want %d: %s", w.Code, c.want, w.Body)
			}
		})
	}
	r := httptest.NewRequest("GET", "/", nil)
	r.Host = "127.0.0.1:8587"
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != http.StatusOK {
		t.Fatalf("static: %d", w.Code)
	}
}
