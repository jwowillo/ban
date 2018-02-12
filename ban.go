package ban

// TODO: Document default behaviors with empty structs and default structs

import (
	"bytes"
	"fmt"
	"io/ioutil"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
)

// Ban ...
type Ban struct {
	PrefixLength byte
	shouldntBan  bool
	shouldBanIP  bool
}

var (
	// DefaultBan ...
	DefaultBan = Ban{shouldBanIP: true}
	// NoBan ...
	NoBan = Ban{shouldntBan: true}
)

// Banner ...
type Banner interface {
	Ban(net.IP, *http.Request) Ban
}

// BannerFunc ...
type BannerFunc func(net.IP, *http.Request) Ban

// Ban ...
func (f BannerFunc) Ban(ip net.IP, r *http.Request) Ban {
	return f(ip, r)
}

// ErrorHandler ...
type ErrorHandler func(error)

// Config ...
type Config struct {
	Store        string
	ErrorHandler ErrorHandler
}

// DefaultConfig ...
var DefaultConfig = Config{}

type handler struct {
	handler http.Handler
	banner  Banner
	config  Config
	ips     *ipMap
}

// StderrErrorHandler ...
func StderrErrorHandler(err error) {
	fmt.Fprintf(os.Stderr, "%v\n", err)
}

// New ...
func New(hh http.Handler, banner Banner, cfg Config) http.Handler {
	h := &handler{
		handler: hh,
		banner:  banner,
		config:  cfg,
		ips:     newIPMap(),
	}
	if h.config.ErrorHandler == nil {
		h.config.ErrorHandler = StderrErrorHandler
	}
	if h.config.Store != "" {
		ips, err := loadBans(h.config.Store)
		if err != nil {
			h.config.ErrorHandler(err)
			ips = newIPMap()
		}
		h.ips = ips
		c := make(chan os.Signal, 2)
		signal.Notify(c, os.Interrupt, syscall.SIGTERM)
		go func() {
			<-c
			if err := h.clean(); err != nil {
				h.config.ErrorHandler(err)
			}
			os.Exit(1)
		}()
	}
	return h
}

func (h *handler) ServeHTTP(rw http.ResponseWriter, r *http.Request) {
	ip, err := parseIP(r.RemoteAddr)
	if err != nil {
		writeBadAddr(rw, r.RemoteAddr)
		h.config.ErrorHandler(err)
		return
	}
	if h.ips.Has(ip) {
		writeBan(rw, ip)
		return
	}
	if ban := h.banner.Ban(ip, r); ban != NoBan {
		var pl byte
		if ban.shouldBanIP {
			pl = byte(len(ip)) * 8
		} else {
			pl = ban.PrefixLength
		}
		if err := h.ips.Add(ip, pl); err != nil {
			h.config.ErrorHandler(err)
		}
		writeBan(rw, ip)
		return
	}
	h.handler.ServeHTTP(rw, r)
}

func (h *handler) clean() error {
	f, err := os.OpenFile(
		h.config.Store,
		os.O_WRONLY|os.O_CREATE|os.O_TRUNC,
		0777,
	)
	if err != nil {
		return err
	}
	defer f.Close()
	for _, ip := range h.ips.IPs() {
		fmt.Fprintf(f, "%v/%d\n", ip.IP, ip.PrefixLength)
	}
	return nil
}

func parseIP(addr string) (net.IP, error) {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, err
	}
	ip := net.ParseIP(host)
	as4 := ip.To4()
	if as4 != nil {
		return as4, nil
	}
	return ip, nil
}

func loadBans(store string) (*ipMap, error) {
	ips := newIPMap()
	bs, err := ioutil.ReadFile(store)
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	for _, line := range bytes.Split(bs, []byte("\n")) {
		if len(line) == 0 {
			continue
		}
		_, ip, err := net.ParseCIDR(string(line))
		if err != nil {
			return nil, err
		}
		pl, _ := ip.Mask.Size()
		ips.Add(ip.IP, byte(pl))
	}
	return ips, nil
}

func writeBadAddr(rw http.ResponseWriter, addr string) {
	fmt.Fprintf(rw, "%s is malformed", addr)
}

func writeBan(rw http.ResponseWriter, ip net.IP) {
	fmt.Fprintf(rw, "%s is banned", ip)
}
