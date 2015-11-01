package canonicalRequest

import (
	"fmt"
	"net/url"
	"sort"
	"strings"

	"github.com/udryan10/hmacurl/utilities"
)

func FormatCanonicalString(method string, url *url.URL, headerMap map[string]string, payload string) string {
	// format string in HTTPRequestMethod, CanonicalURI, CanonicalQueryString, CanonicalHeaders, SignedHeaders, HexEncode(Hash(RequestPayload))
	canonicalQueryStrings := strings.Replace(url.Query().Encode(), "+", "%20", -1)
	canonicalString := fmt.Sprintf("%s\n%s\n%s\n%s\n%s\n%s", method, url.Path, canonicalQueryStrings, formatHeaders(headerMap), FormatSignedHeaders(headerMap), utilities.DataToSha256Encoded([]byte(payload)))
	return canonicalString
}

func formatHeaders(headers map[string]string) string {
	var sorted []string

	for k := range headers {
		sorted = append(sorted, k)
	}
	sort.Strings(sorted)

	headerString := ""
	for _, v := range sorted {
		headerString += fmt.Sprintf("%s:%s\n", strings.TrimSpace(strings.ToLower(v)), strings.TrimSpace(headers[v]))
	}
	return headerString
}

func FormatSignedHeaders(headers map[string]string) string {
	var sorted []string

	for k := range headers {
		sorted = append(sorted, strings.ToLower(k))
	}
	sort.Strings(sorted)
	return strings.Join(sorted, ";")
}
