package utilities

import (
  "crypto/sha256"
  "encoding/hex"
  "fmt"
  )

func DataToSha256Encoded(data []byte) string{
  sha := sha256.Sum256(data)
  return hex.EncodeToString(sha[:])
}

func GenerateSignedHeader(accessKey string, signature string, host string, date string, signedHeaders string) string{
  return fmt.Sprintf("%s Credential=%s/%s/%s/%s/%s, SignedHeaders=%s, Signature=%s", "AWS4-HMAC-SHA256", accessKey, date, "us-east-1", host, "aws4_request", signedHeaders, signature )
}
