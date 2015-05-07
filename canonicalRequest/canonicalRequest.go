package canonicalRequest

import (
  "sort"
  "net/url"
  "strings"
  "fmt"
  "../utilities"
  )


func FormatCanonicalString(method string, url *url.URL, headerMap map[string]string, payload string) string {
  // format string in HTTPRequestMethod, CanonicalURI, CanonicalQueryString, CanonicalHeaders, SignedHeaders, HexEncode(Hash(RequestPayload))
  canonicalString := fmt.Sprintf("%s\n%s\n%s\n%s\n%s\n%s", method, url.Path, url.RawQuery, formatHeaders(headerMap), FormatSignedHeaders(headerMap), utilities.DataToSha256Encoded([]byte(payload)))
  return canonicalString
}

func formatHeaders(headers map[string]string) string {
  var sorted[]string

  for k := range headers {
    sorted = append(sorted,k)
  }
  sort.Strings(sorted)

  headerString := ""
  for _,v := range sorted {
    headerString += fmt.Sprintf("%s:%s\n", strings.TrimSpace(strings.ToLower(v)), strings.TrimSpace(headers[v]))
  }
  return headerString
}

func FormatSignedHeaders(headers map[string]string) string {
  var sorted[]string

  for k := range headers {
    sorted = append(sorted,strings.ToLower(k))
  }
  sort.Strings(sorted)
  return strings.Join(sorted,";")
}
