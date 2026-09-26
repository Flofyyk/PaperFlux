package yandex

import (
	"net/http"
	legacy "universal-bypass-tool/transport/yandex"
)

func solveCaptcha(url string, jar http.CookieJar, userAgent string) (string, error) {
	return legacy.SolveChallenge(url, jar, userAgent)
}
