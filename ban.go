// Package ban is an http.Handler wrapper which allows a Banner to issue Bans
// and supports efficiently adding, checking, and storing them.
//
// Adding and checking the bans is constant-time bounded by the larger of the
// prefix-length being added or the IP-length. Memory use is minimized by not
// restoring duplicate address-parts.
//
// Existing Bans can be loaded into the Handler with new Bans being saved.
package ban

import (
	"fmt"
	"net"
	"net/http"
	"os"
)

// ErrorHandler handles passed errors.
type ErrorHandler func(error)

// IgnoreErrorHandler ignores errors.
func IgnoreErrorHandler(err error) {
}

// StderrErrorHandler writes the error to stderr.
func StderrErrorHandler(err error) {
	fmt.Fprintf(os.Stderr, "%v\n", err)
}

// Ban which can either not ban, ban an IP, or ban a range of IPs by specifying
// the prefix-length of bits in the IP which matter.
//
// An empty Ban bans every IP and shouldn't be used unless that is the desired
// behavior. IPBan bans only the IP which made the http.Request. A Ban with a
// specified prefix-length bans a range of IPs where the bits after the
// prefix-length are ignored when comparing each IP to the one which made the
// http.Request.
type Ban struct {
	PrefixLength byte
	shouldntBan  bool
	shouldBanIP  bool
}

var (
	// IPBan bans only the IP which made the http.Request.
	IPBan = Ban{shouldBanIP: true}
	// NoBan doesn't ban.
	NoBan = Ban{shouldntBan: true}
)

// Banner issues bans to IPs based on http.Requests.
type Banner interface {
	Ban(IP, *http.Request) Ban
}

// BannerFunc is a helper type to convert a function to a Banner.
type BannerFunc func(IP, *http.Request) Ban

// Ban calles the converted function.
func (f BannerFunc) Ban(ip IP, r *http.Request) Ban {
	return f(ip, r)
}

// Config for the wrapper.
type Config struct {
	// StorePath is the name of file to load and store Bans into.
	//
	// Doesn't load or store if not assigned.
	StorePath string
	// ErrorHandler handles errors passed to it.
	//
	// Defaults to StderrErrorHandler if not assigned.
	ErrorHandler ErrorHandler
}

// DefaultConfig which doesn't load or store Bans and uses StderrErrorHandler.
var DefaultConfig = Config{}

// Handler is the wrapping http.Handler which tracks Bans.
type Handler struct {
	handler      http.Handler
	banner       Banner
	ips          ipMap
	errorHandler ErrorHandler
	store        *store
}

// New Handler that wraps the http.Handler to check for Bans issued by the
// Banner before responding to http.Requests with behavior customized by Config.
func New(h http.Handler, banner Banner, cfg Config) *Handler {
	var store *store
	if cfg.StorePath != "" {
		store = newStore(cfg.StorePath)
	}
	errorHandler := cfg.ErrorHandler
	if errorHandler == nil {
		errorHandler = StderrErrorHandler
	}
	hn := &Handler{
		handler:      h,
		banner:       banner,
		ips:          newTrie(),
		errorHandler: errorHandler,
		store:        store,
	}
	if hn.store != nil {
		if err := hn.loadPrefixedIPs(); err != nil {
			hn.errorHandler(err)
		}
	}
	return hn
}

// ServeHTTP checks if the IP that made the http.Request is banned or if it
// should be banned before responding and either writes a banned message or the
// inner http.Handler's response to the http.ResponseWriter.
func (h *Handler) ServeHTTP(rw http.ResponseWriter, r *http.Request) {
	ip, err := parseRemoteAddress(r.RemoteAddr)
	if err != nil {
		h.errorHandler(err)
		writeError(rw, err)
		return
	}
	if h.ips.Has(ip) {
		writeBan(rw, ip)
		return
	}
	if ban := h.banner.Ban(ip, r); ban != NoBan {
		var pl byte
		if ban.shouldBanIP {
			pl = ipLength
		} else {
			pl = ban.PrefixLength
		}
		pip, err := NewPrefixedIP(ip, pl)
		if err != nil {
			h.errorHandler(err)
			writeBan(rw, ip)
			return
		}
		h.ips.Add(pip)
		if h.store != nil {
			if err := h.writePrefixedIP(pip); err != nil {
				h.errorHandler(err)
			}
		}
		writeBan(rw, ip)
		return
	}
	h.handler.ServeHTTP(rw, r)
}

// writePrefixedIP to the store.
//
// Returns any error that happened during writing.
func (h *Handler) writePrefixedIP(pip *PrefixedIP) error {
	return h.store.Add(pip)
}

// loadPrefixedIPs from the store and return an ipMap containing the
// PrefixedIPs.
//
// Returns any error that happened during loading.
func (h *Handler) loadPrefixedIPs() error {
	pips, err := h.store.PrefixedIPs()
	if err != nil {
		return err
	}
	for _, pip := range pips {
		h.ips.Add(pip)
	}
	return nil
}

// parseRemoteAddress parses the IP from an http.Request's remote-address.
//
// Returns an error if the remote-address can't be parsed.
func parseRemoteAddress(addr string) (IP, error) {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return IP{}, ErrBadIP
	}
	return ParseIP(host)
}

// writeBan writes that the IP is banned to the http.ResponseWriter.
func writeBan(rw http.ResponseWriter, ip IP) {
	rw.WriteHeader(http.StatusForbidden)
	fmt.Fprintf(rw, fmt.Sprintf("%v is banned", ip))
}

// writeError to the http.ResponseWriter.
func writeError(rw http.ResponseWriter, err error) {
	rw.WriteHeader(http.StatusInternalServerError)
	fmt.Fprintf(rw, "%s", err)
}

// ipMap is a structure that efficiently supports adding of PrefixedIPs and
// membership checking of IPs.
type ipMap interface {
	Add(*PrefixedIP)
	Has(IP) bool
}
