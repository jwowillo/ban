package ban_test

import (
	"fmt"
	"net/http"

	"github.com/jwowillo/ban"
)

// IsMalicious checks if the http.Request is malicious.
func IsMalicious(r *http.Request) bool {
	return false // This can be anything.
}

// Ban the ban.IP if the http.Request is malicious.
func Ban(ip ban.IP, r *http.Request) ban.Ban {
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
	handler := http.HandlerFunc(Handle)
	banner := ban.BannerFunc(Ban)
	http.ListenAndServe(
		":8080",
		ban.New(handler, banner, ban.DefaultConfig),
	)
}
