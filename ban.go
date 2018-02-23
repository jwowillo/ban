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
	"bytes"
	"fmt"
	"io/ioutil"
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
	// Store is name of file to load and store Bans into.
	//
	// Doesn't load or store if not assigned.
	Store string
	// ErrorHandler handles errors passed to it.
	//
	// Defaults to StderrErrorHandler if not assigned.
	ErrorHandler ErrorHandler
}

// DefaultConfig which doesn't load or store Bans and uses StderrErrorHandler.
var DefaultConfig = Config{}

// Handler is the wrapping http.Handler which tracks Bans.
type Handler struct {
	Handler http.Handler
	banner  Banner
	config  Config
	ips     ipMap
}

// New Handler that wraps the http.Handler to check for Bans issued by the
// Banner before responding to http.Requests with behavior customized by Config.
func New(h http.Handler, banner Banner, cfg Config) *Handler {
	hn := &Handler{Handler: h, banner: banner, config: cfg, ips: newTrie()}
	if hn.config.ErrorHandler == nil {
		hn.config.ErrorHandler = StderrErrorHandler
	}
	if hn.config.Store != "" {
		ips, err := loadPrefixedIPs(hn.config.Store)
		if err != nil {
			ips = newTrie()
			hn.config.ErrorHandler(err)
		}
		hn.ips = ips
	}
	return hn
}

// ServeHTTP checks if the IP that made the http.Request is banned or if it
// should be banned before responding and either writes a banned message or the
// inner http.Handler's response to the http.ResponseWriter.
func (h *Handler) ServeHTTP(rw http.ResponseWriter, r *http.Request) {
	ip, err := parseRemoteAddress(r.RemoteAddr)
	if err != nil {
		h.config.ErrorHandler(err)
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
			h.config.ErrorHandler(err)
			writeBan(rw, ip)
			return
		}
		h.ips.Add(pip)
		if h.config.Store != "" {
			if err := writePrefixedIP(
				h.config.Store,
				pip,
			); err != nil {
				h.config.ErrorHandler(err)
			}
		}
		writeBan(rw, ip)
		return
	}
	h.Handler.ServeHTTP(rw, r)
}

// writePrefixedIP to file at path.
//
// Returns an error if the file couldn't be opened.
func writePrefixedIP(path string, ip *PrefixedIP) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0777)
	if err != nil {
		return err
	}
	defer f.Close()
	fmt.Fprintf(f, "%s\n", ip)
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

// loadPrefixedIPs from file at path store and return an ipMap containing the
// PrefixedIPs.
//
// Returns an error if the file couldn't be read.
func loadPrefixedIPs(store string) (ipMap, error) {
	ips := newTrie()
	bs, err := ioutil.ReadFile(store)
	if err != nil {
		if os.IsNotExist(err) {
			return ips, nil
		}
		return nil, err
	}
	for _, line := range bytes.Split(bs, []byte("\n")) {
		if len(line) == 0 {
			continue
		}
		pip, err := ParsePrefixedIP(string(line))
		if err != nil {
			return nil, err
		}
		ips.Add(pip)
	}
	return ips, nil
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
