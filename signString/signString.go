package signString

import (
	"fmt"
	"time"
)

func StringToSign(requestTime time.Time, canonicalRequest, region, service string) string {
	credentialScope := fmt.Sprintf("%s/%s/%s/%s", requestTime.Format("20060102"), region, service, "aws4_request")
	stringToSign := fmt.Sprintf("%s\n%s\n%s\n%s", "AWS4-HMAC-SHA256", requestTime.Format("20060102T150405Z"), credentialScope, canonicalRequest)
	return stringToSign
}
