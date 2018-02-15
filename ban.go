// Package ban provides an http.Handler wrapper which allows a bans to be issued
// to IP addresses and supports efficiently adding, checking, and storing them.
//
// All IP addresses handled within the package are treated as 16-byte addresses.
// IPv4 addresses are padded to 16 bytes, if necessary, with the prefix
// "::ffff".
//
// Adding and checking the bans is constant time bounded by the length of the
// part of the longest IP address being banned. Memory use is minimized by not
// restoring duplicate address parts.
//
// Existing bans can be loaded into the Handler with new bans being saved.
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

// StderrErrorHandler writes the error to stderr.
func StderrErrorHandler(err error) {
	fmt.Fprintf(os.Stderr, "%v\n", err)
}

// Ban which is issued by a Banner.
//
// The Ban can either not ban, ban an IP address, or ban a range of addresses by
// specifying the prefix-length of bits in the IP address which matter. IP
// addresses handled by this package are always 16 bytes so the prefix-length
// should correspond to a 16-byte address.
//
// An empty Ban bans every address and shouldn't be used unless that is the
// desired behavior. DefaultBan bans only the address which made the request. A
// Ban with a specified PrefixLength bans a range of addresses where the parts
// of the address not covered by the prefix-length can be anything.
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
//
// net.IPs passed from this package will always be 16 bytes long. IPv4 addresses
// are padded to 16 bytes if necessary with the prefix "::ffff".
type Banner interface {
	Ban(net.IP, *http.Request) Ban
}

// BannerFunc is a helper type to convert a function to a Banner.
type BannerFunc func(net.IP, *http.Request) Ban

// Ban calles the converted function.
func (f BannerFunc) Ban(ip net.IP, r *http.Request) Ban {
	return f(ip, r)
}

// Config for the wrapper.
type Config struct {
	// Store is name of file to load and store bans into.
	//
	// Doesn't load or store if not assigned.
	Store string
	// ErrorHandler handles errors passed to it.
	//
	// Defaults to StderrErrorHandler if not assigned.
	ErrorHandler ErrorHandler
}

// DefaultConfig which doesn't load or store bans and uses StderrErrorHandler.
var DefaultConfig = Config{}

// Handler is the wrapping http.Handler which tracks bans.
type Handler struct {
	Handler http.Handler
	banner  Banner
	config  Config
	ips     ipMap
}

// New creates a Handler that wraps the http.Handler to check for bans issued by
// the Banner before responding to http.Requests with behavior customized by
// Config.
func New(h http.Handler, banner Banner, cfg Config) *Handler {
	hn := &Handler{Handler: h, banner: banner, config: cfg, ips: newTrie()}
	if hn.config.ErrorHandler == nil {
		hn.config.ErrorHandler = StderrErrorHandler
	}
	if hn.config.Store != "" {
		ips, err := loadBans(hn.config.Store)
		if err != nil {
			ips = newTrie()
			hn.config.ErrorHandler(err)
		}
		hn.ips = ips
	}
	return hn
}

// ServeHTTP checks if the address that made the http.Request is banned or if it
// should be banned before responding and either writes a banned message or the
// inner http.Handler's response to the http.ResponseWriter.
func (h *Handler) ServeHTTP(rw http.ResponseWriter, r *http.Request) {
	ip := parseIP(r.RemoteAddr)
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
		h.ips.Add(ip, pl)
		if h.config.Store != "" {
			if err := writeIP(h.config.Store, ip, pl); err != nil {
				h.config.ErrorHandler(err)
			}
		}
		return
	}
	h.Handler.ServeHTTP(rw, r)
}

// writeIP with prefix-length to file at path.
//
// Returns an error if the file couldn't be opened..
func writeIP(path string, ip net.IP, pl byte) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0777)
	if err != nil {
		return err
	}
	defer f.Close()
	fmt.Fprintf(f, "%v/%d\n", ip, pl)
	return nil
}

// parseIP parses the net.IP from an http.Request's remote-address.
//
// Returns nil if the net.IP can't be parsed.
func parseIP(addr string) net.IP {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return nil
	}
	ip := net.ParseIP(host)
	if len(ip) == ipv4Length {
		ip = append(ipv4Prefix, ip...)
	}
	return ip
}

// loadBans from file at path store and return an ipMap containing the bans.
//
// Returns an error if the file couldn't be read.
func loadBans(store string) (ipMap, error) {
	ips := newTrie()
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
		ip, mask, err := net.ParseCIDR(string(line))
		if err != nil {
			return nil, err
		}
		pl, _ := mask.Mask.Size()
		ips.Add(ip, byte(pl))
	}
	return ips, nil
}

// writeBan writes that the net.IP is banned to the http.ResponseWriter.
func writeBan(rw http.ResponseWriter, ip net.IP) {
	fmt.Fprintf(rw, "%s is banned", ip)
}

// ipMap is a structure that efficiently supports adding of net.IPs and
// prefix-lengths and membership checking of net.IPs.
//
// All passed addresses can be assumed to be 16 bytes with prefix-lengths in
// terms of 16-byte addresses. IPv4 addresses are padded to 16 bytes, if
// necessary, with the prefix "::ffff".
//
// Malformed addresses and prefix-lengths shouldn't be added.
type ipMap interface {
	Add(net.IP, byte)
	Has(net.IP) bool
}
