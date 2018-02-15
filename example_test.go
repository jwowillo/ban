package ban_test

import (
	"fmt"
	"net"
	"net/http"

	"github.com/jwowillo/ban"
)

// IsMalicious checks if the http.Request is malicious.
func IsMalicious(r *http.Request) bool {
	return false // This can be anything.
}

// Ban the net.IP if the http.Request is malicious.
func Ban(ip net.IP, r *http.Request) ban.Ban {
	if IsMalicious(r) {
		return ban.DefaultBan
	}
	return ban.NoBan
}

// Handle the http.Request by writing response to the http.ResponseWriter.
func Handle(rw http.ResponseWriter, r *http.Request) {
	fmt.Fprintf(rw, "response")
}

func Example() {
	banner := ban.BannerFunc(Ban)
	handler := http.HandlerFunc(Handle)
	http.ListenAndServe(
		":8080",
		ban.New(handler, banner, ban.DefaultConfig),
	)
}
