package ban

import (
	"fmt"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
)

// TestBanBadPrefixLength tests that banning a bad prefix-length triggers the
// ErrorHandler.
func TestBanBadPrefixLength(t *testing.T) {
	t.Parallel()
	h := http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {})
	b := BannerFunc(func(ip IP, r *http.Request) Ban {
		return Ban{PrefixLength: 129}
	})
	called := false
	testHandler(
		t,
		New(h, b, Config{
			ErrorHandler: func(err error) {
				called = true
			},
		}),
		"1.2.3.4", "1.2.3.4 is banned", http.StatusForbidden,
	)
	if !called {
		t.Errorf("bad prefix didn't trigger ErrorHandler")
	}
}

// TestBanBadStore tests that a bad store triggers the ErrorHandler.
func TestBanBadStore(t *testing.T) {
	t.Parallel()
	defer func() {
		if err := os.Remove("bad_store.txt"); err != nil {
			t.Error(err)
		}
	}()
	f, err := os.Create("bad_store.txt")
	if err != nil {
		t.Error(err)
	}
	fmt.Fprintf(f, "bad\n")
	h := http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {})
	b := BannerFunc(func(ip IP, r *http.Request) Ban { return NoBan })
	called := false
	testHandler(
		t,
		New(h, b, Config{
			Store: "bad_store.txt",
			ErrorHandler: func(err error) {
				called = true
			},
		}),
		"1.2.3.4", "", http.StatusOK,
	)
	if !called {
		t.Errorf("ban.New() didn't return error with bad store")
	}
}

// TestBanStore tests that banned IPs are remembered.
func TestBanStore(t *testing.T) {
	t.Parallel()
	defer func() {
		if err := os.Remove("store.txt"); err != nil {
			t.Error(err)
		}
	}()
	h := http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {})
	b := BannerFunc(func(ip IP, r *http.Request) Ban { return IPBan })
	testHandler(
		t,
		New(h, b, Config{Store: "store.txt"}),
		"1.2.3.4", "1.2.3.4 is banned", http.StatusForbidden,
	)
	b = BannerFunc(func(ip IP, r *http.Request) Ban { return NoBan })
	testHandler(
		t,
		New(h, b, Config{Store: "store.txt"}),
		"1.2.3.4", "1.2.3.4 is banned", http.StatusForbidden,
	)
}

// TestBanNotBanned tests that IPs which aren't banned are able to make
// http.Requests.
func TestBanNotBanned(t *testing.T) {
	t.Parallel()
	testBanner(
		t,
		BannerFunc(func(ip IP, r *http.Request) Ban {
			return NoBan
		}),
		[]string{"1.2.3.4"}, []string{""}, []int{http.StatusOK},
	)
	testBanner(
		t,
		BannerFunc(func(ip IP, r *http.Request) Ban {
			if ip.String() == "::1111" {
				return Ban{PrefixLength: 127}
			}
			return NoBan
		}),
		[]string{"::1111", "::2222"},
		[]string{"::1111 is banned", ""},
		[]int{http.StatusForbidden, http.StatusOK},
	)
}

// TestBanBanned tests that IPs which are banned aren't able to make
// http.Requests.
func TestBanBanned(t *testing.T) {
	t.Parallel()
	testBanner(
		t,
		BannerFunc(func(ip IP, r *http.Request) Ban {
			return IPBan
		}),
		[]string{"1.2.3.4"},
		[]string{"1.2.3.4 is banned"},
		[]int{http.StatusForbidden},
	)
	testBanner(
		t,
		BannerFunc(func(ip IP, r *http.Request) Ban {
			if ip.String() == "::1" {
				return Ban{PrefixLength: 126}
			}
			return NoBan
		}),
		[]string{"::1", "::2"},
		[]string{"::1 is banned", "::2 is banned"},
		[]int{http.StatusForbidden, http.StatusForbidden},
	)
}

// TestBanError tests that errors are correctly written to http.Responses.
func TestBanError(t *testing.T) {
	t.Parallel()
	testBanner(
		t,
		BannerFunc(func(ip IP, r *http.Request) Ban {
			return IPBan
		}),
		[]string{""},
		[]string{"bad IP"},
		[]int{http.StatusInternalServerError},
	)
}

// testBanner tests that the Banner returns the correct sequence of codes and
// responses to http.Requests made by the given sequence of IPs.
func testBanner(t *testing.T, b Banner, ip []string, es []string, esc []int) {
	h := http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(rw, "")
	})
	wh := New(h, b, Config{ErrorHandler: IgnoreErrorHandler})
	if len(ip) != len(es) || len(es) != len(esc) {
		t.Errorf("all slices must have the same length")
	}
	for i := 0; i < len(ip); i++ {
		testHandler(t, wh, ip[i], es[i], esc[i])
		testHandler(t, wh, ip[i], es[i], esc[i])
	}
}

// testHandler tests that the http.Handler returns the correct message and code
// with an http.Request from the given IP.
func testHandler(t *testing.T, h http.Handler, ip string, es string, esc int) {
	if strings.Contains(ip, ":") {
		ip = "[" + ip + "]"
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, &http.Request{RemoteAddr: ip + ":"})
	bs, err := ioutil.ReadAll(rec.Result().Body)
	if err != nil {
		t.Error(err)
	}
	if string(bs) != es {
		t.Errorf("r.Body = %s, want %v", bs, es)
	}
	sc := rec.Result().StatusCode
	if sc != esc {
		t.Errorf("r.StatusCode = %d, want %d", sc, esc)
	}
}
