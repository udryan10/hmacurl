package utilities

import (
	"testing"
)

func TestDataToSha256Encoded(t *testing.T) {
	if DataToSha256Encoded([]byte("testString")) != "4acf0b39d9c4766709a3689f553ac01ab550545ffa4544dfc0b2cea82fba02a3" {
		t.Error("DataToSha256Encoded did not work as expected.")
	} else {
		t.Log("One test passed.")
	}
}

func TestGenerateSignedHeader(t *testing.T) {
	if GenerateSignedHeader("testApiKey", "testSignature", "localhost", "20110909", "x-amz-date") != "AWS4-HMAC-SHA256 Credential=testApiKey/20110909/us-east-1/localhost/aws4_request, SignedHeaders=x-amz-date, Signature=testSignature" {
		t.Error("TestGenerateSignedHeader did not work as expected.")
	} else {
		t.Log("One test passed.")
	}
}
