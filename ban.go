// Package ban is an http.Handler wrapper which allows a Banner to issue bans
// and supports efficiently adding, checking, and storing them.
//
// Adding and checking the bans is constant time bounded by the length of the
// part of the longest IP address being banned. Memory use is minimized by not
// restoring duplicate address parts.
//
// Existing bans can be loaded into the wrapper and issued bans can be stored
// when the banning process terminates.
//
// This allows large amounts of addresses to be stored and remembered.
package ban

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

// Ban which is issued by a Banner.
//
// The Ban can either not ban, ban an IP address, or ban a range of addresses by
// specifying the prefix-length of bits in the IP address which matter.
//
// An empty Ban bans every address and shouldn't be used unless that is the
// desired behavior. DefaultBan bans only the address which made the request. A
// Ban with a specified PrefixLength bans the entire range of addresses when
// only that number of bits in the addresses prefix are considered.
type Ban struct {
	PrefixLength byte
	shouldntBan  bool
	shouldBanIP  bool
}

var (
	// DefaultBan bans only the IP address which made the request.
	DefaultBan = Ban{shouldBanIP: true}
	// NoBan doesn't ban.
	NoBan = Ban{shouldntBan: true}
)

// Banner issues bans to net.IPs based on http.Requests.
type Banner interface {
	Ban(net.IP, *http.Request) Ban
}

// BannerFunc is a helper type to convert a function to a Banner.
type BannerFunc func(net.IP, *http.Request) Ban

// Ban calles the converted function.
func (f BannerFunc) Ban(ip net.IP, r *http.Request) Ban {
	return f(ip, r)
}

// ErrorHandler handles an error.
type ErrorHandler func(error)

// StderrErrorHandler prints the error to stderr.
func StderrErrorHandler(err error) {
	fmt.Fprintf(os.Stderr, "%v\n", err)
}

// Config for the wrapper.
type Config struct {
	// Store is name of file to load and store bans into.
	//
	// Doesn't load or store if not assigned.
	Store string
	// ErrorHandler for errors that happen during the banning process.
	//
	// Is StderrErrorHandler if not assigned.
	ErrorHandler ErrorHandler
}

// DefaultConfig which doesn't load or store bans and uses StderrErrorHandler.
var DefaultConfig = Config{}

// handler is the underlying http.Handler which tracks bans and calls the
// wrapped http.Handler.
type handler struct {
	handler http.Handler
	banner  Banner
	config  Config
	ips     *ipMap
}

// Handler wraps the http.Handler to check for bans issued by the Banner before
// responding to http.Requests with behavior customized by Config.
func Handler(h http.Handler, banner Banner, cfg Config) http.Handler {
	hn := &handler{handler: h, banner: banner, config: cfg, ips: newIPMap()}
	if hn.config.ErrorHandler == nil {
		hn.config.ErrorHandler = StderrErrorHandler
	}
	if hn.config.Store != "" {
		ips, err := loadBans(hn.config.Store)
		if err != nil {
			hn.config.ErrorHandler(err)
			ips = newIPMap()
		}
		hn.ips = ips
		c := make(chan os.Signal, 2)
		signal.Notify(c, os.Interrupt, syscall.SIGTERM)
		go func() {
			<-c
			if err := hn.clean(); err != nil {
				hn.config.ErrorHandler(err)
			}
			os.Exit(1)
		}()
	}
	return hn
}

// ServeHTTP checks if the address that made the http.Request is banned or if it
// should be banned before responding and either writes a banned message or the
// inner http.Handler's response to the http.ResponseWriter.
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

// clean the handler by writing all stored addresses to the store.
//
// Returns an error if the store couldn't be written to.
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

// parseIP parses the net.IP from an http.Request's remote-address.
//
// Returns an error if the net.IP can't be parsed.
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

// loadBans from file at path store and return an ipMap containing the bans.
//
// Returns an empty ipMap if the file doesn't exist.
//
// Returns an error if the file couldn't be read.
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

// writeBadAddr writes that the http.Request's remote-address is malformed to
// the http.ResponseWriter.
func writeBadAddr(rw http.ResponseWriter, addr string) {
	fmt.Fprintf(rw, "%s is malformed", addr)
}

// writeBan writes that the net.IP is banned to the http.ResponseWriter.
func writeBan(rw http.ResponseWriter, ip net.IP) {
	fmt.Fprintf(rw, "%s is banned", ip)
}
