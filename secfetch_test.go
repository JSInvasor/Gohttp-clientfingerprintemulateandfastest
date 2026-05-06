package gofire

import (
	"net/http"
	"net/url"
	"testing"
)

func TestSecFetchSiteFor(t *testing.T) {
	cases := []struct {
		name    string
		reqURL  string
		referer string
		want    string
	}{
		{"no referer", "https://target.com/", "", "none"},
		{"empty referer header", "https://target.com/", "", "none"},
		{"same origin", "https://target.com/page", "https://target.com/", "same-origin"},
		{"same origin with port", "https://target.com:8443/", "https://target.com:8443/", "same-origin"},
		{"cross-origin via google", "https://target.com/", "https://www.google.com/", "cross-site"},
		{"cross-origin via duckduckgo", "https://target.com/", "https://duckduckgo.com/", "cross-site"},
		{"same-site subdomain", "https://api.target.com/", "https://www.target.com/", "same-site"},
		{"different scheme same host is same-site", "https://target.com/", "http://target.com/", "same-site"},
		{"different port same host is same-site", "https://target.com/", "https://target.com:8443/", "same-site"},
		{"malformed referer", "https://target.com/", "::::not a url", "none"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			u, _ := url.Parse(tc.reqURL)
			req := &http.Request{URL: u, Header: http.Header{}}
			if tc.referer != "" {
				req.Header.Set("Referer", tc.referer)
			}
			got := secFetchSiteFor(req)
			if got != tc.want {
				t.Errorf("secFetchSiteFor(%q, ref=%q) = %q, want %q", tc.reqURL, tc.referer, got, tc.want)
			}
		})
	}
}
