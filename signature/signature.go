package signature

import (
  "crypto/hmac"
  "crypto/sha256"
  "time"
  "encoding/hex"
  )

func ComputeHmac256(secret []byte, message string) []byte {
  key := []byte(secret)
  h := hmac.New(sha256.New, key)
  h.Write([]byte(message))
  return h.Sum(nil)
}

func calculateSigningKey(requestTime time.Time, service string, secret string) []byte {
  kSecret := secret
  //kDate := ComputeHmac256("AWS4" + kSecret, requestTime.Format("20060102"))
  kDate := ComputeHmac256([]byte("AWS4" + kSecret), requestTime.Format("20060102"))
  kRegion := ComputeHmac256(kDate, "us-east-1")
  kService := ComputeHmac256(kRegion,service)
  kSigning :=  ComputeHmac256(kService, "aws4_request")
  return kSigning
}

func CalculateSignature(requestTime time.Time, message string, service string, secret string) string {
  return hex.EncodeToString(ComputeHmac256(calculateSigningKey(requestTime, service, secret),message))
}
