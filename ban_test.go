package ban_test

import (
	"net"
	"net/http"
	"testing"

	"github.com/jwowillo/ban"
)

func Handle(rw http.ResponseWriter, r *http.Request) {}

func Ban(ip net.IP, r *http.Request) ban.Ban { return ban.DefaultBan }

var (
	Handler = http.HandlerFunc(Handle)
	Banner  = ban.BannerFunc(Ban)
)

func TestBan(t *testing.T) {
	http.ListenAndServe(
		":8080",
		ban.New(Handler, Banner, ban.Config{Store: "out.txt"}),
	)
}
